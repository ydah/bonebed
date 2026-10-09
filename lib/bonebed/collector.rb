# frozen_string_literal: true

module Bonebed
  class Collector
    EVENT_GROUPS = %i[changes processes listen sockets suspicious dns anti_analysis].freeze
    attr_reader :errors, :observer_errors, :wall_ms, :status
    attr_accessor :cleanup_metadata

    def initialize
      @files = {read: Hash.new(0), write: Hash.new(0)}
      @network = Hash.new(0)
      @executions = Hash.new(0)
      @threads = Hash.new(0)
      @errors = []
      @observer_errors = []
      @roundtrips = 0
      @events = EVENT_GROUPS.to_h { |group| [group, Hash.new(0)] }
      @process_tree = {}
    end

    def record_open(event)
      @files.fetch(event.fetch(:mode))[event.fetch(:path)] += 1
    end

    def record_network(event)
      @network[event.freeze] += 1
    end

    def record_exec(event)
      @executions[event.freeze] += 1
    end

    def record_thread(event)
      @threads[event.freeze] += 1
    end

    def record_process(event)
      @process_tree[event.values_at(:pid, :path, :parent)] = event.freeze
    end

    def record_notification
      @roundtrips += 1
    end

    def record(group, event)
      @events.fetch(group)[event.freeze] += 1
    end

    def record_error(context, error)
      @errors << "#{context}: #{error.class}: #{error.message}"
    end

    def record_observer_error(context, error)
      @observer_errors << "#{context}: #{error.class}: #{error.message}"
    end

    def finish(started_at, status, stdout: "", stderr: "", timed_out: false, started_time: nil,
      stdout_truncated: false, stderr_truncated: false, isolation: "none")
      @wall_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at) * 1000).round
      @status = status
      @target = {exit_status: status&.exitstatus, signal: status&.termsig, timed_out:}
      @started_at = started_time
      @isolation = isolation
      @stdout_truncated = stdout_truncated
      @stderr_truncated = stderr_truncated
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
      @events.transform_values { |entries| normalize_events(entries, normalizer) }.merge(
        files: @files.transform_values { |entries| normalize_counts(entries, normalizer) },
        network: normalize_network(normalizer),
        exec: normalize_exec(normalizer),
        process_tree: @process_tree.values.map { |event| normalize_event(event, normalizer) },
        cleanup: @cleanup_metadata&.dup,
        threads: @threads.dup,
        stats: {openat_total: @files.values.sum { |entries| entries.values.sum }, notify_roundtrips: @roundtrips, wall_ms: @wall_ms},
        errors: @errors.dup,
        observer_errors: @observer_errors.dup,
        target: @target || {exit_status: nil, signal: nil, timed_out: false},
        started_at: @started_at,
        isolation: @isolation,
        stdout_truncated: !!@stdout_truncated,
        stderr_truncated: !!@stderr_truncated,
        stdout: @stdout.to_s,
        stderr: @stderr.to_s
      )
    end

    private

    def normalize_events(entries, normalizer)
      entries.each_with_object(Hash.new(0)) do |(event, count), result|
        result[normalize_event(event, normalizer)] += count
      end
    end

    def normalize_event(event, normalizer)
      event.to_h do |key, value|
        normalize = %i[path from to parent].include?(key) && value.is_a?(String) && !(key == :from && event[:symbolic])
        [key, normalize ? normalizer.call(value) : value]
      end
    end

    # ponytail: manifests are text; add base64 fields only if byte-perfect output becomes a requirement.
    def utf8(value)
      value.to_s.b.force_encoding(Encoding::UTF_8).scrub
    end

    def normalize_counts(entries, normalizer)
      entries.each_with_object(Hash.new(0)) { |(path, count), result| result[normalizer.call(path)] += count }
    end

    def normalize_network(normalizer)
      @network.each_with_object(Hash.new(0)) do |(event, count), result|
        normalized = (event[:family] == "unix") ? event.merge(path: normalizer.call(event[:path])) : event
        result[normalized] += count
      end
    end

    def normalize_exec(normalizer)
      @executions.each_with_object(Hash.new(0)) do |(event, count), result|
        result[normalize_event(event, normalizer).merge(argv: event.fetch(:argv).map { |arg| normalizer.scrub(arg) })] += count
      end
    end
  end
end
