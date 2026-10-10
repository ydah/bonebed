# frozen_string_literal: true

require "bonebed/phase/install"
require "bonebed/phase/require"
require "bonebed/phase/plugin"
require "bonebed/policy"
require "socket"
require "rubygems/package"
require "tmpdir"

RSpec.describe "Appendix D adversarial fixtures" do
  before do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")
    require "seccomp/notify"
  end

  around do |example|
    Dir.mktmpdir("bonebed-adversarial-") do |directory|
      @baseline = Bonebed::Baseline.new(cache_dir: File.join(directory, "baselines"))
      example.run
    end
  end

  it "reports synthetic credential reads as sensitive and critical" do
    result = observe("credential-stealer")
    expect(result.dig("files", "notable")).to include("$HOME/.aws/credentials", "$HOME/.ssh/id_ed25519")
    expect(result.dig("capabilities", "sensitive_read")).to be(true)
    expect(result["findings"]).to include(include("rule_id" => "credential-read", "severity" => "critical"))
  end

  it "records a canary in attempted DNS exfiltration without sending it" do
    allow(Bonebed::Isolation).to receive(:offline_command).and_raise(Bonebed::Isolation::Unavailable, "fixture exercises fallback")
    result = observe("env-exfil", offline: true)
    expect(result["dns"]).to include(include("name" => "[CANARY:env:GITHUB_TOKEN].example.invalid"))
    expect(result["canary_hits"]).to include(include("source" => "env:GITHUB_TOKEN", "seen_in" => "dns"))
    expect(result["network"]).to include(include("addr" => "127.0.0.1", "port" => 53), include("addr" => "127.0.0.1", "port" => 9))
    expect(result["stdout"]).to include("dns blocked", "http blocked")
    expect(result.fetch("network_intent", [])).to be_empty
  end

  it "captures the env-exfil HTTP hostname and canary inside the sinkhole" do
    result = observe("env-exfil", sinkhole: true, env: {"BONEBED_FIXTURE_SINKHOLE" => "1"})
    expect(result.fetch("network_intent")).to include(include("protocol" => "http", "host" => "[CANARY:env:GITHUB_TOKEN].example.invalid", "path" => "/"))
    expect(result["canary_hits"]).to include(include("source" => "env:GITHUB_TOKEN", "seen_in" => "network_intent"))
  end

  it "executes only the local true ELF via memfd and execveat" do
    result = observe("fileless")
    expect(result["suspicious"]).to include(include("syscall" => "memfd_create"), include("syscall" => "execveat"))
    expect(result["findings"]).to include(include("rule_id" => "fileless-exec", "severity" => "critical"))
    expect(result.dig("target", "exit_status")).to eq(0)
  end

  it "attributes shell startup modification to the plugin phase" do
    result = observe("plugin-persist", phase: "plugin")
    expect(result["phase"]).to eq("plugin")
    expect(result.dig("files", "write")).to include("$HOME/.bashrc")
    expect(result.dig("capabilities", "home_write")).to be(true)
  end

  it "records project hook creation and permission changes" do
    result = observe("pwd-tamper")
    expect(result.dig("files", "write")).to include("$PWD/.git/hooks/pre-commit")
    expect(result.dig("files", "chmod")).to include(include("path" => "$PWD/.git/hooks/pre-commit", "mode" => 0o700))
    expect(result["findings"]).to include(include("rule_id" => "git-hook-write", "severity" => "critical"))
  end

  it "observes a local curl-to-shell extension build without remote content" do
    server = TCPServer.new("127.0.0.1", 0)
    worker = Thread.new do
      client = server.accept
      client.readpartial(4096)
      body = "printf fixture > \"$HOME/dropper-marker\"\n"
      client.write("HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
      client.close
    end
    result = observe("extconf-dropper", phase: "install", env: {"BONEBED_FIXTURE_PORT" => server.addr[1].to_s})
    expect(result["exec"].map { |entry| File.basename(entry["path"]) }).to include("curl", "sh")
    expect(result["network"]).to include(include("addr" => "127.0.0.1", "port" => server.addr[1]))
    expect(result.dig("files", "write")).to include("$HOME/dropper-marker")
    expect(result["findings"]).to include(include("rule_id" => "install-network"))
  ensure
    worker&.kill
    worker&.join
    server&.close
  end

  it "distinguishes CI-only communication from the default environment" do
    normal = observe("ci-only")
    ci = observe("ci-only", env: {"CI" => "true"}, profile: "ci")
    expect(normal["network"]).to be_empty
    expect(ci["network"]).to include(include("addr" => "127.0.0.1", "port" => 9))
  end

  it "observes at_exit communication in the require phase" do
    result = observe("at-exit")
    expect(result["phase"]).to eq("require")
    expect(result["network"]).to include(include("addr" => "127.0.0.1", "port" => 9))
  end

  it "cleans up double-forked detached children without a timeout" do
    result = observe("daemonize")
    expect(result.dig("target", "timed_out")).to be(false)
    expect(result["processes"]).not_to be_empty
    pid = Integer(result.fetch("stdout").strip)
    expect { Process.kill(0, pid) }.to raise_error(Errno::ESRCH)
  end

  it "records a loopback listener" do
    result = observe("server")
    expect(result["listen"]).to include(include("family" => "inet", "addr" => "127.0.0.1", "syscall" => "listen"))
  end

  it "blocks unconnected UDP and leaves the local receiver empty" do
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    allow(Bonebed::Isolation).to receive(:offline_command).and_raise(Bonebed::Isolation::Unavailable, "fixture exercises fallback")
    result = observe("udp-noconnect", offline: true, env: {"BONEBED_FIXTURE_PORT" => socket.addr[1].to_s})
    expect(result["network"]).to include(include("addr" => "127.0.0.1", "port" => socket.addr[1]))
    expect(result["stdout"]).to include("udp blocked")
    expect { socket.recv_nonblock(1024) }.to raise_error(IO::WaitReadable)
  ensure
    socket&.close
  end

  it "blocks unconnected UDP using the available offline isolation mode" do
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    result = observe("udp-noconnect", offline: true, env: {"BONEBED_FIXTURE_PORT" => socket.addr[1].to_s})
    expect(result.dig("run", "mode", "isolation")).to satisfy { |mode| %w[network_namespace syscall_fallback].include?(mode) }
    expect(result["stdout"]).to include("udp blocked")
    expect { socket.recv_nonblock(1024) }.to raise_error(IO::WaitReadable)
  ensure
    socket&.close
  end

  it "records seccomp detection even when the fixture takes no further action" do
    result = observe("anti-analysis")
    expect(result["anti_analysis"]).to include(include("path" => "/proc/self/status"))
    expect(result["stdout"]).to include("seccomp detected")
  end

  it "records netlink destinations without decoding errors" do
    result = observe("netlink")
    expect(result["network"]).to include(include("family" => "netlink"))
  end

  it "records io_uring_setup and returns ENOSYS" do
    result = observe("io-uring")
    expect(result["suspicious"]).to include(include("syscall" => "io_uring_setup"))
    expect(result["stdout"]).to include("ENOSYS")
  end

  def observe(name, phase: "require", env: {}, offline: false, sinkhole: false, profile: "dev")
    source = File.join(__dir__, "fixtures", "gems", "malicious", name)
    specification = Gem::Specification.load(File.join(source, "bonebed-fixture-#{name}.gemspec"))
    raise "missing fixture #{name}" unless specification

    Bonebed::GemEnvironment.open do |environment|
      if %w[fileless io-uring].include?(name)
        fiddle = Gem::Specification.find_by_name("fiddle")
        environment.copy_gems(fiddle) unless fiddle.default_gem?
      end
      environment.env["BONEBED_ADVERSARIAL_FIXTURE"] = "1"
      %i[memfd_create execveat io_uring_setup].each do |syscall|
        environment.env["BONEBED_SYSCALL_#{syscall.upcase}"] = Seccomp::Notify::Syscalls.number(syscall).to_s
      end
      environment.env.merge!(env)
      FileUtils.cp_r(File.join(source, "."), environment.prefetch)
      package = Dir.chdir(environment.prefetch) { Gem::DefaultUserInteraction.use_ui(Gem::SilentUI.new) { Gem::Package.build(specification) } }
      options = {quiet_target: true, timeout: 10, offline:, sinkhole:}
      installed = Bonebed::Phase::Install.call(environment, [File.join(environment.prefetch, package)], **options)
      expect(installed.errors).to be_empty, installed.snapshot(environment.normalizer)[:stderr]
      collector = case phase
      when "install" then installed
      when "plugin" then Bonebed::Phase::Plugin.call(environment, **options)
      else Bonebed::Phase::Require.call(environment, specification, **options).first
      end
      snapshot = collector.snapshot(environment.normalizer)
      expect(snapshot[:errors]).to be_empty, snapshot[:stderr]
      expect(snapshot[:observer_errors].reject { |error| error.start_with?("isolation:") }).to be_empty
      baseline = @baseline.capture(phase:, offline:, sinkhole:, env_profile: profile)
      manifest = Bonebed::ManifestBuilder.call(specification.name, specification.version.to_s, phase, snapshot, baseline,
        specifications: [specification], run: {"mode" => {"offline" => offline, "env_profile" => profile}})
      manifest = environment.honeypot.redact(manifest)
      manifest["findings"] = Bonebed::Policy.new.findings(manifest)
      manifest
    end
  end
end
