# frozen_string_literal: true

require "json"

module Bonebed
  class Collector
    EVENT_GROUPS = %i[changes processes listen sockets suspicious dns anti_analysis].freeze
    attr_reader :errors, :observer_errors, :wall_ms, :status
    attr_accessor :cleanup_metadata
    attr_accessor :network_intent

    TransportStatus = Struct.new(:exitstatus, :termsig) do
      def success?
        exitstatus == 0 && termsig.nil?
      end

      def signaled?
        !termsig.nil?
      end
    end

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
      @network_intent = []
      @denied = Hash.new(0)
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
      @process_tree[event.values_at(:pid, :path, :parent, :cwd)] = event.freeze
    end

    def record_notification
      @roundtrips += 1
    end

    def record_denial(event)
      @denied[event.freeze] += 1
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
        network_intent: @network_intent.map(&:dup),
        denied: @denied.dup,
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

    def export_state
      state = {
        "files" => @files.transform_keys(&:to_s),
        "events" => @events.transform_keys(&:to_s).transform_values { |entries| transport_entries(entries) },
        "network" => transport_entries(@network), "executions" => transport_entries(@executions),
        "threads" => transport_entries(@threads), "process_tree" => @process_tree.values,
        "errors" => @errors, "observer_errors" => @observer_errors, "roundtrips" => @roundtrips,
        "wall_ms" => @wall_ms, "target" => @target || {exit_status: nil, signal: nil, timed_out: false},
        "started_at" => @started_at, "isolation" => @isolation || "none",
        "stdout" => @stdout.to_s, "stderr" => @stderr.to_s,
        "stdout_truncated" => !!@stdout_truncated, "stderr_truncated" => !!@stderr_truncated,
        "cleanup" => @cleanup_metadata, "network_intent" => @network_intent, "denied" => transport_entries(@denied)
      }
      JSON.parse(JSON.generate(state), max_nesting: 32)
    end

    def import_state!(data)
      expected = export_state.keys
      raise ArgumentError, "invalid collector state" unless data.is_a?(Hash) && data.keys.sort == expected.sort
      data = JSON.parse(JSON.generate(data), max_nesting: 32)
      files = data.fetch("files")
      raise ArgumentError, "invalid file counters" unless files.is_a?(Hash) && files.keys.sort == %w[read write]
      @files = files.to_h do |mode, entries|
        valid = entries.is_a?(Hash) && entries.all? { |path, count| path.is_a?(String) && count.is_a?(Integer) && count.positive? }
        raise ArgumentError, "invalid file counters" unless valid
        [mode.to_sym, Hash.new(0).merge(entries)]
      end
      events = data.fetch("events")
      raise ArgumentError, "invalid event groups" unless events.is_a?(Hash) && events.keys.sort == EVENT_GROUPS.map(&:to_s).sort
      @events = events.to_h { |group, entries| [group.to_sym, restore_entries(entries)] }
      @network = restore_entries(data.fetch("network"))
      @executions = restore_entries(data.fetch("executions"))
      @threads = restore_entries(data.fetch("threads"))
      @denied = restore_entries(data.fetch("denied"))
      tree = data.fetch("process_tree")
      raise ArgumentError, "invalid process tree" unless tree.is_a?(Array) && tree.all? { |event| event.is_a?(Hash) }
      @process_tree = tree.to_h { |event|
        event = event.transform_keys(&:to_sym)
        [event.values_at(:pid, :path, :parent, :cwd), event]
      }
      %w[errors observer_errors].each do |field|
        values = data.fetch(field)
        raise ArgumentError, "invalid #{field}" unless values.is_a?(Array) && values.all? { |value| value.is_a?(String) }
        instance_variable_set("@#{field}", values.dup)
      end
      %w[stdout stderr isolation].each do |field|
        raise ArgumentError, "invalid #{field}" unless data[field].is_a?(String)
        instance_variable_set("@#{field}", data.fetch(field))
      end
      %w[stdout_truncated stderr_truncated].each do |field|
        raise ArgumentError, "invalid #{field}" unless [true, false].include?(data[field])
        instance_variable_set("@#{field}", data.fetch(field))
      end
      target = data.fetch("target")
      valid = target.is_a?(Hash) && target.keys.sort == %w[exit_status signal timed_out] &&
        [true, false].include?(target["timed_out"]) &&
        (target["exit_status"].nil? || (target["exit_status"].is_a?(Integer) && target["exit_status"].between?(0, 255))) &&
        (target["signal"].nil? || (target["signal"].is_a?(Integer) && target["signal"].positive?)) &&
        (target["exit_status"].nil? || target["signal"].nil?)
      raise ArgumentError, "invalid target status" unless valid
      @target = target.transform_keys(&:to_sym)
      @status = @target.values_at(:exit_status, :signal).all?(&:nil?) ? nil : TransportStatus.new(@target[:exit_status], @target[:signal])
      valid_timing = data["roundtrips"].is_a?(Integer) && data["roundtrips"] >= 0 && (data["wall_ms"].nil? || (data["wall_ms"].is_a?(Integer) && data["wall_ms"] >= 0))
      raise ArgumentError, "invalid timing or counters" unless valid_timing
      raise ArgumentError, "invalid started_at" unless data["started_at"].nil? || data["started_at"].is_a?(String)
      raise ArgumentError, "invalid cleanup metadata" unless data["cleanup"].nil? || data["cleanup"].is_a?(Hash)
      intents = data.fetch("network_intent")
      valid_intents = intents.is_a?(Array) && intents.all? do |event|
        event.is_a?(Hash) && event.all? { |key, value| (key == "count") ? value.is_a?(Integer) && value.positive? : value.is_a?(String) }
      end
      raise ArgumentError, "invalid network intent" unless valid_intents
      @network_intent = intents
      @roundtrips, @wall_ms, @started_at = data.values_at("roundtrips", "wall_ms", "started_at")
      @cleanup_metadata = data["cleanup"]&.dup
      self
    rescue KeyError, NoMethodError, TypeError, JSON::JSONError => error
      raise ArgumentError, "invalid collector state: #{error.message}"
    end

    private

    def transport_entries(entries)
      entries.map { |event, count| {"event" => event, "count" => count} }
    end

    def restore_entries(entries)
      raise ArgumentError, "invalid event counters" unless entries.is_a?(Array)
      entries.each_with_object(Hash.new(0)) do |entry, result|
        valid = entry.is_a?(Hash) && entry.keys.sort == %w[count event] && entry["event"].is_a?(Hash) &&
          entry["event"].keys.all? { |key| key.is_a?(String) } && entry["count"].is_a?(Integer) && entry["count"].positive?
        raise ArgumentError, "invalid event counters" unless valid
        event = entry.fetch("event").transform_keys(&:to_sym)
        event[:operation] = event[:operation].to_sym if event[:operation].is_a?(String)
        result[event] += entry.fetch("count")
      end
    end

    def normalize_events(entries, normalizer)
      entries.each_with_object(Hash.new(0)) do |(event, count), result|
        result[normalize_event(event, normalizer)] += count
      end
    end

    def normalize_event(event, normalizer)
      event.to_h do |key, value|
        normalize = %i[path from to parent cwd].include?(key) && value.is_a?(String) && !(key == :from && event[:symbolic])
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
