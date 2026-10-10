# frozen_string_literal: true

require "bonebed/isolation"

RSpec.describe Bonebed::Isolation do
  it "reports namespace availability from a disposable child without changing the caller" do
    skip "Linux namespaces are required" unless RUBY_PLATFORM.include?("linux")

    before = File.readlink("/proc/self/ns/net")
    features = described_class.features
    expect(File.readlink("/proc/self/ns/net")).to eq(before)
    expect(features[:landlock_abi]).to be_nil.or be_a(Integer)
    expect(features[:network_namespace]).to be(true).or be(false)
    expect(features[:network_namespace_error]).to be_a(String) unless features[:network_namespace]
  end

  it "raises a clear error when namespace creation is denied" do
    allow(described_class).to receive(:syscall!).with(:unshare, anything).and_raise(described_class::Unavailable, "unshare: Operation not permitted")
    expect { described_class.offline! }.to raise_error(described_class::Unavailable, /unshare.*not permitted/)
  end

  it "runs the external namespace wrapper under seccomp and blocks UDP without syscall rejection" do
    skip "Linux namespaces are required" unless RUBY_PLATFORM.include?("linux")

    code = <<~RUBY
      require "socket"
      begin
        UDPSocket.new.send("probe", 0, "192.0.2.1", 9)
        abort "UDP escaped"
      rescue Errno::ENETUNREACH
        puts "isolated"
      end
    RUBY
    begin
      command = described_class.offline_command([RbConfig.ruby, "-e", code])
    rescue described_class::Unavailable => error
      expect(error.message).to match(/namespace|unshare/)
      next
    end
    result = Bonebed::Session.new(command, offline: false, quiet_target: true, timeout: 5).run.snapshot(Bonebed::PathNormalizer.new)
    expect(result.fetch(:errors)).to be_empty
    expect(result.fetch(:observer_errors)).to be_empty
    expect(result.fetch(:stdout)).to eq("isolated\n")
  end

  it "reports denied external namespaces rather than returning an unisolated command" do
    allow(File).to receive(:executable?).and_return(true)
    allow(Open3).to receive(:capture3).and_return(["", "unshare: Operation not permitted", double(success?: false)])
    expect { described_class.offline_command(["ruby", "-e", ""]) }.to raise_error(described_class::Unavailable, /Operation not permitted/)
  end

  it "blocks unconnected UDP and enables loopback when namespaces are available" do
    skip "Linux namespaces are required" unless RUBY_PLATFORM.include?("linux")

    reader, writer = IO.pipe
    pid = fork do
      reader.close
      begin
        described_class.offline!
        socket = UDPSocket.new
        socket.bind("127.0.0.1", 0)
        # UDPSocket#send needs payload bytes, not a method name for Object#send.
        socket.send("loopback", 0, "127.0.0.1", socket.addr[1]) # standard:disable Performance/StringIdentifierArgument
        raise "loopback failed" unless IO.select([socket], nil, nil, 1) && socket.recv(32) == "loopback"

        begin
          socket.send("probe", 0, "192.0.2.1", 9) # standard:disable Performance/StringIdentifierArgument
          writer.write("unexpected external UDP success")
        rescue Errno::ENETUNREACH
          writer.write("isolated")
        end
      rescue Bonebed::Isolation::Unavailable => error
        writer.write("unavailable: #{error.message}")
      ensure
        writer.close
      end
      exit! 0
    end
    writer.close
    result = reader.read
    Process.wait(pid)
    expect(result).to eq("isolated").or start_with("unavailable: ")
    expect(result).to include("network namespace unavailable") if result.start_with?("unavailable:")
  ensure
    reader&.close
    writer&.close unless writer&.closed?
  end

  it "tracks and kills only the selected descendant, leaving an unrelated child alive" do
    skip "Linux pidfds are required" unless RUBY_PLATFORM.include?("linux")

    reader, writer = IO.pipe
    target = fork do
      reader.close
      child = fork { sleep 30 }
      writer.puts(child)
      writer.close
      Process.wait(child)
      exit! 0
    end
    writer.close
    child = Integer(reader.gets)
    unrelated = fork { sleep 30 }
    tracked = described_class.descendants(target)
    expect(tracked).to have_key(child)
    expect(tracked).not_to have_key(unrelated)
    expect(described_class.cleanup(tracked)).to be_empty
    Process.wait(target)
    expect(Process.kill(0, unrelated)).to eq(1)
  ensure
    reader&.close
    writer&.close unless writer&.closed?
    [child, target, unrelated].compact.each do |pid|
      Process.kill("KILL", pid)
    rescue Errno::ESRCH
      nil
    end
    [target, unrelated].compact.each do |pid|
      Process.wait(pid)
    rescue Errno::ECHILD
      nil
    end
  end

  it "does not signal a PID whose identity changed since tracking" do
    allow(described_class).to receive(:process_info).with(123).and_return({parent: 1, started_at: 456})
    expect(described_class).not_to receive(:syscall!)
    expect(described_class.cleanup(123 => 789)).to be_empty
  end

  it "reaps a tracked orphan that detached from its parent's process group" do
    skip "Linux subreapers are required" unless RUBY_PLATFORM.include?("linux")

    reader, writer = IO.pipe
    supervisor = fork do
      reader.close
      described_class.subreaper!
      child_reader, child_writer = IO.pipe
      gate_reader, gate_writer = IO.pipe
      target = fork do
        child_reader.close
        gate_writer.close
        child = fork do
          Process.setsid
          child_writer.close
          gate_reader.close
          sleep 30
          exit! 0
        end
        child_writer.puts(child)
        child_writer.close
        gate_reader.read(1)
        exit! 0
      end
      child_writer.close
      gate_reader.close
      orphan = Integer(child_reader.gets)
      tracked = described_class.descendants(target)
      gate_writer.write("x")
      gate_writer.close
      Process.wait(target)
      errors = described_class.cleanup(tracked)
      writer.write(JSON.generate({errors:, tracked: tracked.key?(orphan), alive: !described_class.process_info(orphan).nil?}))
      writer.close
      exit! 0
    end
    writer.close
    result = JSON.parse(reader.read)
    Process.wait(supervisor)
    expect(result).to eq("errors" => [], "tracked" => true, "alive" => false)
  ensure
    reader&.close
    writer&.close unless writer&.closed?
  end
end
