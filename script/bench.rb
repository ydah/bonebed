# frozen_string_literal: true

require "bonebed"
require "json"
require "rbconfig"

command = [RbConfig.ruby, "-e", '1000.times { File.read("/etc/hostname") }']
writes_only = ENV["BONEBED_BENCH_WRITES_ONLY"] == "1"
samples = Array.new(3) do
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  raise "plain target failed" unless system(*command, out: File::NULL, err: File::NULL)

  plain = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  collector = Bonebed::Session.new(command, quiet_target: true, writes_only:).run
  observed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
  raise "observation failed" unless collector.errors.empty? && collector.observer_errors.empty?

  {plain_ms: (plain * 1000).round, observed_ms: (observed * 1000).round,
   ratio: (observed / plain).round(2), notifications: collector.snapshot(Bonebed::PathNormalizer.new).dig(:stats, :notify_roundtrips)}
end
puts JSON.pretty_generate(ruby: RUBY_VERSION, arch: RbConfig::CONFIG["host_cpu"], writes_only:, samples:)
