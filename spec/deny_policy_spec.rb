# frozen_string_literal: true

require "socket"

RSpec.describe "Best-effort policy denial" do
  def context(config = {}, name: "example", phase: "require")
    {"config" => config, "name" => name, "phase" => phase}
  end

  def custom(*patterns)
    {"rules" => {"custom" => [{"id" => "fixture-deny", "severity" => "high", "match" => patterns}]}}
  end

  def observe(code, environment:, deny:, **options)
    Bonebed::Session.new([RbConfig.ruby, "-e", code], env: environment.env, cwd: environment.project,
      unsetenv_others: true, quiet_target: true, deny:, **options).run.snapshot(environment.normalizer)
  end

  before { skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux") }

  it "denies a credential read while retaining the attempted capability and explicit evidence" do
    Bonebed::GemEnvironment.open do |environment|
      code = 'begin; File.read(File.join(ENV.fetch("HOME"), ".aws/credentials")); abort "read allowed"; rescue Errno::EPERM; puts "denied"; end'
      result = observe(code, environment:, deny: context)
      expect(result[:stdout]).to eq("denied\n")
      expect(result[:errors]).to be_empty
      expect(result[:observer_errors]).to be_empty
      expect(result.dig(:files, :read)).to include("$HOME/.aws/credentials")
      expect(result[:denied].keys).to include(include(capability: "file:read:$HOME/.aws/credentials", rule_id: "credential-read"))
    end
  end

  it "honors per-gem phase allow rules and severity thresholds" do
    Bonebed::GemEnvironment.open do |environment|
      config = {"allow" => {"example" => {"require" => ["file:read:$HOME/.aws/**"]}}}
      result = observe('puts File.read(File.join(ENV.fetch("HOME"), ".aws/credentials")).length', environment:, deny: context(config))
      expect(result[:errors]).to be_empty
      expect(result[:denied]).to be_empty
      config = {"defaults" => {"fail_on" => "critical"}, "rules" => {"custom" => [{"id" => "write", "severity" => "high", "match" => ["file:write:**"]}]}}
      result = observe('File.write("allowed", "ok")', environment:, deny: context(config))
      expect(result[:errors]).to be_empty
      expect(result[:denied]).to be_empty
    end
  end

  it "checks readable descriptors even when RDWR or CREAT also makes them write observations" do
    Bonebed::GemEnvironment.open do |environment|
      code = <<~RUBY
        path = File.join(ENV.fetch("HOME"), ".aws/credentials")
        [File::RDWR, File::RDONLY | File::CREAT].each do |flags|
          begin; File.open(path, flags) { |file| file.read }; abort "read allowed"; rescue Errno::EPERM; puts "denied"; end
        end
      RUBY
      result = observe(code, environment:, deny: context)
      expect(result[:stdout]).to eq("denied\n" * 2)
      expect(result[:errors]).to be_empty
      expect(result[:observer_errors]).to be_empty
      expect(result[:denied].keys).to include(include(capability: "file:read:$HOME/.aws/credentials"))
    end
  end

  it "blocks writes, renames and child exec but permits the initial launcher" do
    Bonebed::GemEnvironment.open do |environment|
      File.write(File.join(environment.project, "source"), "ok")
      code = <<~RUBY
        [-> { File.write("blocked", "bad") }, -> { File.rename("source", "dest") }, -> { Process.spawn("/bin/true") }].each do |action|
          begin; action.call; abort "operation allowed"; rescue Errno::EPERM; puts "denied"; end
        end
      RUBY
      result = observe(code, environment:, deny: context(custom("file:write:$PWD/**", "file:rename:$PWD/**", "exec:**")))
      expect(result[:stdout]).to eq("denied\n" * 3)
      expect(result[:errors]).to be_empty
      expect(result[:observer_errors]).to be_empty
      expect(File.exist?(File.join(environment.project, "blocked"))).to be(false)
      expect(File.exist?(File.join(environment.project, "source"))).to be(true)
      expect(result[:denied].keys.map { |event| event[:capability] }).to include("exec:/bin/true")
    end
  end

  it "blocks decoded UDP destinations and prevents delivery to a local receiver" do
    UDPSocket.open do |receiver|
      receiver.bind("127.0.0.1", 0)
      Bonebed::GemEnvironment.open do |environment|
        code = <<~RUBY
          require "socket"
          socket = UDPSocket.new
          begin; socket.send("probe", 0, "127.0.0.1", #{receiver.addr[1]}); abort "sent"; rescue Errno::EPERM; puts "denied"; end
        RUBY
        result = observe(code, environment:, deny: context(custom("network:inet:127.0.0.1:*")))
        expect(result[:stdout]).to eq("denied\n")
        expect(result[:errors]).to be_empty
        expect(result[:observer_errors]).to be_empty
        expect(receiver.recv_nonblock(100, exception: false)).to eq(:wait_readable)
      end
    end
  end

  it "matches open creation flags, socket creation and DNS names before continuation" do
    Bonebed::GemEnvironment.open do |environment|
      config = custom("file:create:$PWD/**", "socket:inet:1:*", "network:dns:blocked.example.invalid")
      code = <<~'RUBY'
        require "socket"
        actions = [-> { File.write("created", "bad") }, -> { Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0) }]
        name = "blocked.example.invalid".split(".").map { |part| [part.bytesize].pack("C") + part }.join + "\0"
        packet = [1, 0x100, 1, 0, 0, 0].pack("n6") + name + [1, 1].pack("n2")
        socket = UDPSocket.new
        actions << -> { socket.send(packet, 0, "127.0.0.1", 53) }
        actions.each do |action|
          begin; action.call; abort "allowed"; rescue Errno::EPERM; puts "denied"; end
        end
      RUBY
      result = observe(code, environment:, deny: context(config))
      expect(result[:stdout]).to eq("denied\n" * 3)
      expect(result[:errors]).to be_empty
      expect(result[:observer_errors]).to be_empty
      expect(File.exist?(File.join(environment.project, "created"))).to be(false)
      expect(result[:denied].keys.map { |event| event[:capability] }).to include("network:dns:blocked.example.invalid")
    end
  end

  it "continues undecodable requests with an observer error instead of claiming a boundary" do
    Bonebed::GemEnvironment.open do |environment|
      allow(Bonebed::Decoder::Openat).to receive(:call).and_wrap_original do |original, *arguments, **keywords|
        event = original.call(*arguments, **keywords)
        raise IOError, "synthetic argument-copy race" if event[:path].end_with?("/undecodable")
        event
      end
      result = observe('File.write("undecodable", "continued")', environment:, deny: context(custom("file:write:$PWD/**")))
      expect(File.read(File.join(environment.project, "undecodable"))).to eq("continued")
      expect(result[:errors]).to be_empty
      expect(result[:observer_errors]).to include(include("synthetic argument-copy race"))
      expect(result[:denied]).to be_empty
    end
  end

  it "transports denial context and evidence through the sinkhole worker" do
    Bonebed::GemEnvironment.open do |environment|
      result = observe('begin; File.read(File.join(ENV.fetch("HOME"), ".aws/credentials")); rescue Errno::EPERM; puts "denied"; end',
        environment:, deny: context, sinkhole: true)
      expect(result[:stdout]).to eq("denied\n")
      expect(result[:observer_errors]).to be_empty
      expect(result[:denied].keys).to include(include(capability: "file:read:$HOME/.aws/credentials"))
    end
  end

  it "rejects malformed policies and incompatible writes-only capture before execution" do
    expect { Bonebed::Session.new(["false"], deny: context, writes_only: true) }.to raise_error(ArgumentError, /writes.only/)
    expect { Bonebed::Session.new(["false"], deny: context({"unknown" => true})) }.to raise_error(ArgumentError, /policy/)
  end

  it "retains a denied capability for policy checks after baseline subtraction" do
    capability = "file:read:$HOME/.aws/credentials"
    evidence = {"syscall" => "openat", "capability" => capability, "rule_id" => "credential-read", "severity" => "critical", "count" => 2}
    observation = {files: {read: {"$HOME/.aws/credentials" => 2}, write: {}}, network: {}, exec: {}, threads: {},
                   stats: {openat_total: 2, notify_roundtrips: 2, wall_ms: 1}, errors: [],
                   denied: {evidence.except("count").transform_keys(&:to_sym) => 2}}
    baseline = Bonebed::Baseline::Result.new(id: "fixture", observation: observation)
    manifest = Bonebed::ManifestBuilder.call("example", "1.0.0", "require", observation, baseline)
    expect(manifest.dig("files", "read", "other")).to be_empty
    expect(manifest["denied"]).to eq([evidence])
    expect(Bonebed::CapabilityKeys.counts(manifest)).to eq(capability => 2)
    expect(Bonebed::Policy.new.violations(manifest)).to include(include("rule_id" => "credential-read"))
    manifest["files"] = {"read" => [{"path" => "$HOME/.aws/credentials", "count" => 4}]}
    expect(Bonebed::CapabilityKeys.counts(manifest)).to eq(capability => 4)
  end
end
