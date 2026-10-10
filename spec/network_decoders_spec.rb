# frozen_string_literal: true

require "bonebed/decoder/dns"
require "bonebed/decoder/datagram"

RSpec.describe Bonebed::Decoder::DNS do
  def query(name = "api.example.invalid")
    [1, 0x100, 1, 0, 0, 0].pack("n6") + name.split(".").map { |label| [label.bytesize].pack("C") + label }.join + "\0" + [1, 1].pack("n2")
  end

  it "extracts complete questions and rejects truncated labels and question fields" do
    packet = query
    expect(described_class.questions(packet)).to eq(["api.example.invalid"])
    (0...packet.bytesize).each { |length| expect(described_class.questions(packet.byteslice(0, length))).to eq([]) }
    packet.setbyte(2, 0x81)
    expect(described_class.questions(packet)).to eq([])
  end

  it "bounds names and questions and rejects compression loops" do
    header = [1, 0x100, 1, 0, 0, 0].pack("n6")
    expect(described_class.questions(header + "\xc0\x0c".b + [1, 1].pack("n2"))).to eq([])
    expect(described_class.questions(query((["a" * 63] * 4).join(".")))).to eq([])
    payload = [1, 0x100, 5, 0, 0, 0].pack("n6") + query("a").byteslice(12..) * 5
    expect(described_class.questions(payload)).to eq(["a"] * 4)
  end

  it "handles arbitrary bytes without exceptions or invalid output encoding" do
    binary_name = [1, 0x100, 1, 0, 0, 0].pack("n6") + "\x02\xff.\0".b + [1, 1].pack("n2")
    expect(described_class.questions(binary_name)).to eq(["\\255\\046"])
    random = Random.new(42)
    1000.times do
      names = described_class.questions(random.bytes(random.rand(0..512)))
      expect(names.length).to be <= 4
      expect(names).to all(satisfy(&:valid_encoding?))
    end
  end
end

RSpec.describe Bonebed::Decoder::Datagram do
  def request(args, memory)
    double("request", args:).tap do |request|
      allow(request).to receive(:read) { |address, length| memory.fetch(address).byteslice(0, length) }
    end
  end

  def header(name: 0, length: 0, iov: 200, count: 1)
    [name, length, iov, count, 0, 0, 0].pack("Q<L<x4Q<Q<Q<Q<L<x4")
  end

  it "decodes sendto and caps payload reads before accessing target memory" do
    address = [2, 53, 0x7f000001, 0].pack("S<nNQ<")
    target = request([9, 100, 1 << 32, 0, 200, 16], 100 => "x" * 4096, 200 => address)
    expect(described_class.call(target, syscall: :sendto)).to eq([
      {fd: 9, destination: {family: "inet", addr: "127.0.0.1", port: 53}, payload: "x" * 4096}
    ])
    expect(target).to have_received(:read).with(100, 4096)
  end

  it "gathers sendmsg iovecs and leaves connected destinations unknown" do
    target = request([9, 100, 0], 100 => header(count: 2), 200 => [300, 2].pack("Q<2"),
      216 => [400, 3].pack("Q<2"), 300 => "he", 400 => "llo")
    expect(described_class.call(target, syscall: :sendmsg)).to eq([{fd: 9, destination: nil, payload: "hello"}])
  end

  it "decodes mmsghdr with its LP64 padding and bounds the message count" do
    memory = 16.times.to_h { |index| [100 + index * 64, header(count: 0)] }
    target = request([9, 100, 1000, 0], memory)
    expect(described_class.call(target, syscall: :sendmmsg)).to eq([{fd: 9, destination: nil, payload: ""}] * 16)
    expect(target).to have_received(:read).exactly(16).times
  end

  it "caps iovec counts and aggregate payload bytes" do
    memory = {100 => header(count: 1 << 32), 300 => "x" * 4096}
    16.times { |index| memory[200 + index * 16] = [300, 1].pack("Q<2") }
    target = request([9, 100, 0], memory)
    expect(described_class.call(target, syscall: :sendmsg).first.fetch(:payload)).to eq("x" * 16)
    memory[200] = [300, 1 << 32].pack("Q<2")
    expect(described_class.call(target, syscall: :sendmsg).first.fetch(:payload).bytesize).to eq(4096)
  end

  it "rejects oversized sockaddr lengths before reading and rejects short headers" do
    target = request([9, 100, 0, 0, 200, 129], {})
    expect { described_class.call(target, syscall: :sendto) }.to raise_error(ArgumentError, /sockaddr/)
    expect(target).not_to have_received(:read)
    target = request([9, 100, 0], 100 => "\0" * 55)
    expect { described_class.call(target, syscall: :sendmsg) }.to raise_error(ArgumentError, /short/)
  end

  it "bounds arbitrary msghdr memory reads and rejects malformed or truncated structures" do
    random = Random.new(20261010)
    500.times do
      reads = 0
      bytes = 0
      target = double("fuzz request", args: [9, random.rand(1..65535), random.rand(0..32)])
      allow(target).to receive(:read) do |_address, length|
        reads += 1
        bytes += length
        expect(length).to be_between(1, described_class::MAX_PAYLOAD)
        expect(reads).to be <= 16 * 34
        expect(bytes).to be <= 16 * (56 + 128 + 16 * 16 + 4096)
        data = if length == described_class::MSGHDR_SIZE
          header(name: [0, 100].sample(random:), length: random.rand(0..150), count: [0, 1, 16, 2**64 - 1].sample(random:))
        elsif length == 16
          [300, [0, 1, 4096, 2**64 - 1].sample(random:)].pack("Q<2")
        else
          random.bytes(length)
        end
        random.rand(4).zero? ? data.byteslice(0, random.rand(length)) : data
      end
      begin
        events = described_class.call(target, syscall: [:sendmsg, :sendmmsg].sample(random:))
        expect(events.size).to be <= described_class::MAX_MESSAGES
        expect(events).to all(satisfy { |event| event.fetch(:payload).bytesize <= described_class::MAX_PAYLOAD })
      rescue ArgumentError
        # Invalid pointer contents are expected; unexpected decoder exceptions fail this example.
      end
    end
  end
end
