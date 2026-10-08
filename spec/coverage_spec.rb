# frozen_string_literal: true

RSpec.describe "expanded syscall observation" do
  before { skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux") }

  it "records file changes, child processes and listening sockets" do
    Dir.mktmpdir do |root|
      code = <<~RUBY
        require "socket"
        Dir.mkdir("created")
        File.write("created/a", "x")
        File.rename("created/a", "created/b")
        File.chmod(0600, "created/b")
        File.unlink("created/b")
        Process.wait(fork { exit! 0 })
        TCPServer.new("127.0.0.1", 0).close
      RUBY
      observation = Bonebed::Session.new([RbConfig.ruby, "-e", code], cwd: root).run.snapshot(Bonebed::PathNormalizer.new(cwd: root))
      expect(observation[:observer_errors]).to be_empty
      expect(observation[:processes]).not_to be_empty
      expect(observation[:listen].keys).to include(include(family: "inet", addr: "127.0.0.1"))
      expect(observation[:sockets].keys).to include(include(family: "inet", type: 1))
      expect(observation[:changes].keys).to include(include(operation: :create, path: "$PWD/created/a"),
        include(operation: :truncate, path: "$PWD/created/a"))
      expect(observation[:changes].keys).to include(include(operation: :rename, from: "$PWD/created/a", to: "$PWD/created/b"),
        include(operation: :delete, path: "$PWD/created/b"), include(operation: :chmod, mode: 0o600))
    end
  end

  it "records DNS intent from unconnected UDP and refuses the send in offline mode" do
    code = <<~'RUBY'
      require "socket"
      packet = [1, 0x100, 1, 0, 0, 0].pack("n6") + "\x05probe\x07example\x07invalid\0" + [1, 1].pack("n2")
      socket = UDPSocket.new
      begin
        socket.send(packet, 0, "127.0.0.1", 53)
        abort "send was not refused"
      rescue Errno::ENETUNREACH
      end
    RUBY
    observation = Bonebed::Session.new([RbConfig.ruby, "-e", code], offline: true).run.snapshot(Bonebed::PathNormalizer.new)
    expect(observation[:errors]).to be_empty
    expect(observation[:observer_errors]).to be_empty
    expect(observation[:dns].keys).to include(name: "probe.example.invalid")
    expect(observation[:network].keys).to include(family: "inet", addr: "127.0.0.1", port: 53)
  end

  it "observes RubyGems plugins in their own phase" do
    Bonebed::GemEnvironment.open do |environment|
      FileUtils.mkdir_p(File.join(environment.gem_home, "plugins"))
      File.write(File.join(environment.gem_home, "plugins", "demo_plugin.rb"), 'File.write(File.expand_path("~/.bashrc"), "fixture")')
      collector = Bonebed::Phase::Plugin.call(environment, quiet_target: true)
      expect(collector.errors).to be_empty
      expect(collector.snapshot(environment.normalizer).dig(:files, :write)).to have_key("$HOME/.bashrc")
    end
  end

  it "filters reads in write-only mode and keeps writes" do
    Dir.mktmpdir do |root|
      collector = Bonebed::Session.new([RbConfig.ruby, "-e", 'File.read("/etc/hosts"); File.write("created", "x")'], cwd: root, writes_only: true).run
      observation = collector.snapshot(Bonebed::PathNormalizer.new(cwd: root))
      expect(observation[:observer_errors]).to be_empty
      expect(observation.dig(:files, :read)).to be_empty
      expect(observation.dig(:files, :write)).to have_key("$PWD/created")
    end
  end

  it "does not attribute a reused descriptor to a closed UDP socket" do
    code = <<~RUBY
      require "socket"
      socket = UDPSocket.new
      socket.connect("127.0.0.1", 12345)
      socket.close
      socket = UDPSocket.new
      begin
        socket.send("fixture", 0)
      rescue Errno::EDESTADDRREQ
      end
    RUBY
    observation = Bonebed::Session.new([RbConfig.ruby, "-e", code], quiet_target: true).run.snapshot(Bonebed::PathNormalizer.new)
    expect(observation[:observer_errors]).to be_empty
    expect(observation[:errors]).to be_empty
    expect(observation[:network].fetch({family: "inet", addr: "127.0.0.1", port: 12345})).to eq(1)
  end
end
