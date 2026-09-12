# frozen_string_literal: true

module Bonebed
  class Collector
    attr_reader :errors, :wall_ms, :status

    def initialize
      @files = {read: Hash.new(0), write: Hash.new(0)}
      @network = Hash.new(0)
      @executions = Hash.new(0)
      @errors = []
      @roundtrips = 0
    end

    def record_open(event)
      @files.fetch(event.fetch(:mode))[event.fetch(:path)] += 1
    end

    def record_network(event)
      @network[event.freeze] += 1
    end

    def record_exec(event)
      @executions[[event.fetch(:path), event.fetch(:argv).freeze].freeze] += 1
    end

    def record_notification
      @roundtrips += 1
    end

    def record_error(context, error)
      @errors << "#{context}: #{error.class}: #{error.message}"
    end

    def finish(started_at, status, stdout: "", stderr: "")
      @wall_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at) * 1000).round
      @status = status
      @stdout = utf8(stdout)
      @stderr = utf8(stderr)
      return if status.nil? || status.success?

      @errors << if status&.signaled?
        "target terminated by signal #{status.termsig}"
      else
        "target exited with status #{status&.exitstatus || "unknown"}"
      end
    end

    def snapshot(normalizer)
      {
        files: @files.transform_values { |entries| normalize_counts(entries, normalizer) },
        network: normalize_network(normalizer),
        exec: normalize_exec(normalizer),
        stats: {openat_total: @files.values.sum { |entries| entries.values.sum }, notify_roundtrips: @roundtrips, wall_ms: @wall_ms},
        errors: @errors.dup,
        stdout: @stdout.to_s,
        stderr: @stderr.to_s
      }
    end

    private

    # ponytail: manifests are text; add base64 fields only if byte-perfect output becomes a requirement.
    def utf8(value)
      value.to_s.b.force_encoding(Encoding::UTF_8).scrub
    end

    def normalize_counts(entries, normalizer)
      entries.each_with_object(Hash.new(0)) { |(path, count), result| result[normalizer.call(path)] += count }
    end

    def normalize_network(normalizer)
      @network.each_with_object(Hash.new(0)) do |(event, count), result|
        normalized = event[:family] == "unix" ? event.merge(path: normalizer.call(event[:path])) : event
        result[normalized] += count
      end
    end

    def normalize_exec(normalizer)
      @executions.each_with_object(Hash.new(0)) do |((path, argv), count), result|
        result[{path: normalizer.call(path), argv:}] += count
      end
    end
  end
end
