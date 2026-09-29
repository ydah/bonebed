# frozen_string_literal: true

RSpec.describe Bonebed::Collector do
  it "does not add an unknown exit error after a known timeout" do
    collector = described_class.new
    collector.record_error("session", Timeout::Error.new("timed out"))

    collector.finish(Process.clock_gettime(Process::CLOCK_MONOTONIC), nil)

    expect(collector.errors).to eq(["session: Timeout::Error: timed out"])
  end

  it "makes captured output safe for JSON" do
    collector = described_class.new
    collector.finish(Process.clock_gettime(Process::CLOCK_MONOTONIC), nil,
      stdout: [0xe2, 0x80, 0x98].pack("C*"), stderr: [0xff].pack("C"))

    observation = collector.snapshot(Bonebed::PathNormalizer.new)

    expect(observation.values_at(:stdout, :stderr)).to eq(["‘", "�"])
    expect { JSON.generate(observation) }.not_to raise_error
  end

  it "counts thread creation syscalls" do
    collector = described_class.new
    collector.record_thread(syscall: "clone")
    collector.record_thread(syscall: "clone")

    expect(collector.snapshot(Bonebed::PathNormalizer.new)[:threads]).to eq({{syscall: "clone"} => 2})
  end
end
