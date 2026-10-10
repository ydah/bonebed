# frozen_string_literal: true

require "bonebed"
require "json"
require "rbconfig"
require "etc"

command = [RbConfig.ruby, "-e", '1000.times { File.read("/etc/hostname") }']
writes_only = ENV["BONEBED_BENCH_WRITES_ONLY"] == "1"
samples = Array.new(3) do
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  raise "plain target failed" unless system(*command, out: File::NULL, err: File::NULL)

  plain = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  collector = Bonebed::Session.new(command, quiet_target: true, writes_only:).run
  observed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
  raise "observation failed" unless collector.errors.empty? && collector.observer_errors.empty? && collector.status&.success?

  {plain_ms: (plain * 1000).round, observed_ms: (observed * 1000).round,
   ratio: (observed / plain).round(2), notifications: collector.snapshot(Bonebed::PathNormalizer.new).dig(:stats, :notify_roundtrips)}
end
cpu = File.read("/proc/cpuinfo").lines.filter_map { |line| line.split(":", 2).last&.strip if line.match?(/\A(?:model name|CPU part|Hardware)\s*:/) }.uniq.join("; ")
puts JSON.pretty_generate(schema_version: 1, environment: {
  ruby: RUBY_VERSION, arch: RbConfig::CONFIG["host_cpu"], kernel: `uname -r`.strip,
  cpu: cpu.empty? ? nil : cpu, cpus: Etc.nprocessors, workload: "read-hostname-1000-v1", writes_only:,
  tool: "bonebed", tool_version: Bonebed::VERSION, seccomp_notify: Gem.loaded_specs.fetch("seccomp-notify").version.to_s
}, samples:)
