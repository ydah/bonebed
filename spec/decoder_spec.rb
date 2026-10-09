# frozen_string_literal: true

RSpec.describe Bonebed::Decoder do
  describe Bonebed::Decoder::Connect do
    it "records non-IP socket families without raising" do
      expect(described_class.call([16, 0, 0, 0].pack("S<S<L<L<"))).to eq(family: "netlink")
      expect(described_class.call([99, 0].pack("S<S<"))).to eq(family: "af_99")
      expect { described_class.call("\0") }.to raise_error(ArgumentError)
      expect { described_class.call([2].pack("S<")) }.to raise_error(ArgumentError)
    end

    it "decodes Linux IPv4, IPv6, and Unix socket addresses" do
      ipv4 = [2].pack("S<") + [443].pack("n") + [127, 0, 0, 1].pack("C4") + ("\0" * 8)
      ipv6 = [10, 443, 0].pack("S<nN") + [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].pack("n8") + [0].pack("L<")
      unix = [1].pack("S<") + "/tmp/bonebed.sock\0"

      expect(described_class.call(ipv4)).to eq(family: "inet", addr: "127.0.0.1", port: 443)
      expect(described_class.call(ipv6)).to eq(family: "inet6", addr: "2001:db8::1", port: 443)
      expect(described_class.call(unix)).to eq(family: "unix", path: "/tmp/bonebed.sock")
      expect(described_class.call([0].pack("S<"))).to be_nil
      expect(described_class.call([1].pack("S<"))).to eq(family: "unix", path: "")
    end

    it "bounds arbitrary sockaddr input and returns well-formed endpoints" do
      random = Random.new(7331)
      500.times do
        bytes = [random.rand(0..40)].pack("S<") + random.bytes(random.rand(0..140))
        begin
          event = described_class.call(bytes)
          next unless event

          expect(event.fetch(:family)).to be_a(String)
          expect(event.fetch(:path)).to be_a(String) if event[:family] == "unix"
          expect(event.fetch(:port)).to be_between(0, 65_535) if %w[inet inet6].include?(event[:family])
        rescue ArgumentError
          expect(bytes.bytesize > 128 || ([2, 10].include?(bytes.unpack1("S<")) && bytes.bytesize < 28)).to be(true)
        end
      end
    end
  end

  describe Bonebed::Decoder::Openat do
    it "reads openat arguments and classifies access mode" do
      request = instance_double("request", args: [0, 123, File::RDWR])
      allow(request).to receive(:read_string).with(123).and_return("/tmp/demo")

      expect(described_class.call(request, syscall: :openat)).to eq(path: "/tmp/demo", mode: :write)
    end

    it "resolves relative paths from the target cwd" do
      at_fdcwd = (1 << 32) - 100
      request = instance_double("request", args: [at_fdcwd, 123, File::RDONLY], pid: 42)
      allow(request).to receive(:read_string).with(123).and_return("./log/demo.log")
      allow(File).to receive(:readlink).with("/proc/42/cwd").and_return("/app")

      expect(described_class.call(request, syscall: :openat)).to eq(path: "/app/log/demo.log", mode: :read)
    end

    it "resolves relative paths from an openat directory descriptor" do
      request = instance_double("request", args: [7, 123, File::RDONLY], pid: 42)
      allow(request).to receive(:read_string).with(123).and_return("demo.yml")
      allow(File).to receive(:readlink).with("/proc/42/fd/7").and_return("/app/config")

      expect(described_class.call(request, syscall: :openat)).to eq(path: "/app/config/demo.yml", mode: :read)
    end

    it "falls back to the target cwd when procfs is unavailable" do
      at_fdcwd = (1 << 64) - 100
      request = instance_double("request", args: [at_fdcwd, 123, File::RDONLY], pid: 42)
      allow(request).to receive(:read_string).with(123).and_return("missing")
      allow(File).to receive(:readlink).with("/proc/42/cwd").and_raise(Errno::EACCES)

      expect(described_class.call(request, syscall: :openat, cwd: "/app")).to eq(path: "/app/missing", mode: :read)
    end

    it "classifies file creation as a write" do
      request = instance_double("request", args: [0, 123, File::RDONLY | File::CREAT])
      allow(request).to receive(:read_string).with(123).and_return("/tmp/demo")

      expect(described_class.call(request, syscall: :openat)).to eq(path: "/tmp/demo", mode: :write)
    end
  end

  describe Bonebed::Decoder::Execve do
    it "reads a native pointer array up to its NULL terminator" do
      pointer_size = [0].pack("J").bytesize
      request = instance_double("request", args: [100, 200])
      allow(request).to receive(:read_string).with(100).and_return("/usr/bin/echo")
      allow(request).to receive(:read).with(200, pointer_size).and_return([300].pack("J"))
      allow(request).to receive(:read).with(200 + pointer_size, pointer_size).and_return([0].pack("J"))
      allow(request).to receive(:read_string).with(300).and_return("echo")

      expect(described_class.call(request)).to eq(path: "/usr/bin/echo", argv: ["echo"])
    end
  end

  describe Bonebed::Decoder::Clone do
    it "identifies clone thread creation from CLONE_THREAD" do
      request = instance_double("request", args: [0x00010000])

      expect(described_class.call(request, syscall: :clone)).to eq(syscall: "clone")
      expect(described_class.call(instance_double("request", args: [0]), syscall: :clone)).to be_nil
    end

    it "reads clone3 flags from the target" do
      request = instance_double("request", args: [100, 88])
      allow(request).to receive(:read).with(100, 8).and_return([0x00010000].pack("Q<"))

      expect(described_class.call(request, syscall: :clone3)).to eq(syscall: "clone3")
    end

    it "rejects short clone3 reads and handles arbitrary flag bits" do
      random = Random.new(42)
      request = double("request", args: [100, 88])
      (0...8).each do |length|
        allow(request).to receive(:read).with(100, 8).and_return(random.bytes(length))
        expect { described_class.call(request, syscall: :clone3) }.to raise_error(ArgumentError, /short/)
      end
      200.times do
        flags = random.rand(0...(1 << 64))
        allow(request).to receive(:read).with(100, 8).and_return([flags].pack("Q<"))
        expected = (flags & described_class::CLONE_THREAD).zero? ? nil : {syscall: "clone3"}
        expect(described_class.call(request, syscall: :clone3)).to eq(expected)
      end
    end
  end
end
