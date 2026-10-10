# frozen_string_literal: true

RSpec.describe "Sinkhole resolver injection" do
  it "provides independent read descriptors without changing the host resolver" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")

    original = File.binread("/etc/resolv.conf")
    Tempfile.create("bonebed-resolver") do |file|
      file.write("nameserver 127.0.0.1\n")
      file.flush
      code = '2.times { print File.binread("/etc/resolv.conf") }'
      result = Bonebed::Session.new([RbConfig.ruby, "--disable-gems", "-e", code], resolver_file: file.path,
        writes_only: true, quiet_target: true).run.snapshot(Bonebed::PathNormalizer.new)
      expect(result.fetch(:stdout)).to eq("nameserver 127.0.0.1\n" * 2)
      expect(result.fetch(:errors)).to be_empty
      expect(result.fetch(:observer_errors)).to be_empty
      expect(result.dig(:files, :read)).to be_empty
      expect(File.binread("/etc/resolv.conf")).to eq(original)
    end
  end

  it "rejects attempts to write the intercepted resolver" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")

    Tempfile.create("bonebed-resolver") do |file|
      file.write("nameserver 127.0.0.1\n")
      file.flush
      code = 'begin; File.write("/etc/resolv.conf", "bad"); abort "write accepted"; rescue Errno::EACCES; puts "denied"; end'
      result = Bonebed::Session.new([RbConfig.ruby, "--disable-gems", "-e", code], resolver_file: file.path,
        quiet_target: true).run.snapshot(Bonebed::PathNormalizer.new)
      expect(result.fetch(:stdout)).to eq("denied\n")
      expect(result.fetch(:errors)).to be_empty
    end
  end

  it "rejects incompatible sinkhole settings before starting a target" do
    expect { Bonebed::Session.new(["false"], sinkhole: true, offline: true) }.to raise_error(ArgumentError, /offline/)
    expect { Bonebed::Session.new(["false"], sinkhole: true, trace: "out.jsonl") }.to raise_error(ArgumentError, /trace/)
  end

  it "intercepts openat2 and preserves close-on-exec" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")

    Tempfile.create("bonebed-resolver") do |file|
      file.write("nameserver 127.0.0.1\n")
      file.flush
      code = <<~RUBY
        require "fiddle"
        call = Fiddle::Function.new(Fiddle::Handle::DEFAULT["syscall"], [Fiddle::TYPE_LONG] * 5, Fiddle::TYPE_LONG)
        path = Fiddle::Pointer["/etc/resolv.conf\\0"]
        how = Fiddle::Pointer[[0x80000, 0, 0].pack("Q<3")]
        fd = call.call(437, -100, path.to_i, how.to_i, 24)
        abort "openat2 failed" if fd < 0
        io = IO.for_fd(fd)
        print io.read
        puts io.close_on_exec?
        io.close
      RUBY
      result = Bonebed::Session.new([RbConfig.ruby, "-e", code], resolver_file: file.path,
        quiet_target: true).run.snapshot(Bonebed::PathNormalizer.new)
      expect(result.fetch(:stdout)).to eq("nameserver 127.0.0.1\ntrue\n")
      expect(result.fetch(:errors)).to be_empty
      expect(result.fetch(:observer_errors)).to be_empty
    end
  end

  it "blocks host Unix sockets that could bypass the synthetic DNS service" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")

    Dir.mktmpdir do |root|
      resolver = File.join(root, "resolv.conf")
      File.write(resolver, "nameserver 127.0.0.1\n")
      path = File.join(root, "service.sock")
      server = UNIXServer.new(path)
      code = 'require "socket"; begin; UNIXSocket.new(ARGV.fetch(0)); abort "connected"; rescue Errno::ENETUNREACH, Errno::EAFNOSUPPORT; puts "denied"; end'
      result = Bonebed::Session.new([RbConfig.ruby, "-e", code, path], resolver_file: resolver,
        quiet_target: true).run.snapshot(Bonebed::PathNormalizer.new)
      expect(result.fetch(:stdout)).to eq("denied\n")
      expect(result.fetch(:errors)).to be_empty
      expect(IO.select([server], nil, nil, 0)).to be_nil
    ensure
      server&.close
    end
  end

  it "rejects Unix sockets even when the target makes its address memory unreadable" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")

    Dir.mktmpdir do |root|
      resolver = File.join(root, "resolv.conf")
      File.write(resolver, "nameserver 127.0.0.1\n")
      path = File.join(root, "service.sock")
      server = UNIXServer.new(path)
      number = Bonebed::Isolation::SYSCALLS.fetch(RbConfig::CONFIG.fetch("host_cpu")).fetch(:prctl)
      require "seccomp/notify"
      socket_number = Seccomp::Notify::Syscalls.number(:socket)
      code = <<~RUBY
        require "socket"
        require "fiddle"
        call = Fiddle::Function.new(Fiddle::Handle::DEFAULT["syscall"], [Fiddle::TYPE_LONG] * 6, Fiddle::TYPE_LONG)
        abort "prctl failed" if call.call(#{number}, 4, 0, 0, 0, 0) < 0
        begin
          UNIXSocket.new(ARGV.fetch(0))
          abort "connected"
        rescue Errno::ENETUNREACH, Errno::EAFNOSUPPORT
          puts "denied"
        end
        begin
          Socket.pair(Socket::AF_UNIX, Socket::SOCK_DGRAM, 0)
          abort "socketpair accepted"
        rescue Errno::EAFNOSUPPORT
          puts "pair denied"
        end
        fd = call.call(#{socket_number}, (1 << 32) | 1, 1, 0, 0, 0)
        abort "wide Unix family accepted" if fd >= 0
        abort "unexpected socket error" unless Fiddle.last_error == Errno::EAFNOSUPPORT::Errno
        puts "wide family denied"
      RUBY
      result = Bonebed::Session.new([RbConfig.ruby, "-e", code, path], resolver_file: resolver,
        quiet_target: true).run.snapshot(Bonebed::PathNormalizer.new)
      expect(result.fetch(:stdout)).to eq("denied\npair denied\nwide family denied\n")
      expect(IO.select([server], nil, nil, 0)).to be_nil
    ensure
      server&.close
    end
  end
end
