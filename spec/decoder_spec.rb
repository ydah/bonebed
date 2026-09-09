# frozen_string_literal: true

RSpec.describe Bonebed::Decoder do
  describe Bonebed::Decoder::Connect do
    it "decodes Linux IPv4, IPv6, and Unix socket addresses" do
      ipv4 = [2].pack("S<") + [443].pack("n") + [127, 0, 0, 1].pack("C4") + ("\0" * 8)
      ipv6 = [10, 443, 0].pack("S<nN") + [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].pack("n8") + [0].pack("L<")
      unix = [1].pack("S<") + "/tmp/bonebed.sock\0"

      expect(described_class.call(ipv4)).to eq(family: "inet", addr: "127.0.0.1", port: 443)
      expect(described_class.call(ipv6)).to eq(family: "inet6", addr: "2001:db8::1", port: 443)
      expect(described_class.call(unix)).to eq(family: "unix", path: "/tmp/bonebed.sock")
    end
  end

  describe Bonebed::Decoder::Openat do
    it "reads openat arguments and classifies access mode" do
      request = instance_double("request", args: [0, 123, File::RDWR])
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
end
