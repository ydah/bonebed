# frozen_string_literal: true

require "json"
require_relative "result_store"
require_relative "manifest_diff"
require_relative "policy"

module Bonebed
  module NightlyRegression
    MAX_FILES = 1000
    MAX_BYTES = 16 * 1024 * 1024
    BENCH_ENVIRONMENT = %w[ruby arch kernel cpu cpus workload writes_only seccomp_notify tool tool_version].freeze
    METRICS = %w[plain_ms observed_ms ratio notifications].freeze

    module_function

    def read(directory)
      result = {"manifests" => [], "errors" => []}
      paths = ResultStore.paths(directory)
      raise ArgumentError, "too many observation files" if paths.size > MAX_FILES
      result["errors"] << {"path" => ".", "error" => "no observation files"} if paths.empty?
      paths.each do |path|
        raise ArgumentError, "manifest exceeds size limit" if File.size(path) > MAX_BYTES
        manifest = JSON.parse(File.read(path), max_nesting: 64)
        raise ArgumentError, "invalid manifest" unless ResultStore.valid?(manifest)
        CapabilityKeys.call(manifest)
        result["manifests"] << manifest
      rescue JSON::ParserError, ArgumentError, SystemCallError => error
        result["errors"] << {"path" => path.delete_prefix("#{directory}/"), "error" => error.message}
      end
      result
    end

    def compare(current:, previous:)
      before = Array(previous).group_by { |manifest| [manifest["phase"], manifest.dig("gem", "name")] }
      after = current.group_by { |manifest| [manifest["phase"], manifest.dig("gem", "name")] }
      rows = (before.keys | after.keys).sort.map do |phase, name|
        old = before.fetch([phase, name], [])
        fresh = after.fetch([phase, name], [])
        row = {"gem" => name, "phase" => phase, "before_versions" => old.map { |entry| entry.dig("gem", "version") },
               "after_versions" => fresh.map { |entry| entry.dig("gem", "version") }}
        reason = if fresh.empty?
          "missing_current"
        elsif previous.nil?
          "no_previous_observations"
        elsif old.empty?
          "new_target"
        elsif old.size != 1 || fresh.size != 1
          "ambiguous_observations"
        else
          incompatible(old.first, fresh.first)
        end
        if reason
          row.merge("status" => %w[missing_current new_target].include?(reason) ? reason : "not_compared", "reason" => reason,
            "before_errors" => old.flat_map { |entry| errors(entry) }, "after_errors" => fresh.flat_map { |entry| errors(entry) })
        else
          delta = ManifestDiff.call(old.first, fresh.first)
          row.merge(delta).merge("status" => "compared", "before_version" => old.first.dig("gem", "version"),
            "after_version" => fresh.first.dig("gem", "version"), "version_changed" => old.first.dig("gem", "version") != fresh.first.dig("gem", "version"),
            "runtime" => runtime(fresh.first), "mode" => fresh.first.dig("run", "mode"),
            "findings" => Policy.new.findings(fresh.first, keys: delta.fetch("added")))
        end
      end
      {"schema_version" => 1, "observations" => rows, "summary" => rows.group_by { |row| row.fetch("status") }.transform_values(&:size),
       "limitation" => "Observed capability changes and incomplete comparisons; this report is not a safety verdict."}
    end

    def incompatible(before, after)
      return "current_failed" unless errors(after).empty?
      return "previous_failed" unless errors(before).empty?
      return "unknown_runtime" unless [before, after].all? { |entry| runtime(entry).values.all? { |value| value.is_a?(String) && !value.empty? } }
      return "unknown_mode" unless [before, after].all? { |entry| known_mode?(entry.dig("run", "mode")) }
      return "runtime_changed" unless runtime(before) == runtime(after)
      return "mode_changed" unless mode(before) == mode(after)
      return "invocation_changed" unless invocation(before) == invocation(after)
      nil
    end

    def runtime(manifest)
      environment = manifest["environment"] || {}
      result = environment.slice("ruby", "arch", "kernel")
      %w[ruby arch kernel].each { |key| result[key] ||= nil }
      %w[name version seccomp_notify].each { |key| result["tool_#{key}"] = manifest.dig("tool", key) }
      result["bundler"] = environment["bundler"] if %w[bundle bundler_plugin].include?(manifest["phase"])
      result
    end

    def invocation(manifest)
      manifest.fetch("gem").values_at("platform", "require_path") + [manifest["command"], manifest.dig("run", "executable"), manifest.dig("run", "arguments")]
    end

    def mode(manifest)
      [ResultStore.mode_identity(manifest.dig("run", "mode")), manifest.dig("run", "mode", "isolation")]
    end

    def known_mode?(mode)
      mode.is_a?(Hash) && %w[offline honeypot writes_only real_home].all? { |key| [true, false].include?(mode[key]) } &&
        %w[dev ci prod].include?(mode["env_profile"]) && mode["isolation"].is_a?(String)
    end

    def errors(manifest)
      result = Array(manifest["errors"]) + Array(manifest["observer_errors"])
      target = manifest["target"] || {}
      result << "target status unknown" unless target["exit_status"].is_a?(Integer) || target["signal"].is_a?(Integer)
      result << "target timed out" if target["timed_out"]
      result << "target signal #{target["signal"]}" if target["signal"]
      result << "target status #{target["exit_status"]}" if target["exit_status"] && target["exit_status"] != 0
      result << manifest["failure_reason"] if manifest["failure_reason"]
      result
    end

    def benchmark(current, previous)
      return {"status" => "not_compared", "reason" => "no_current_benchmark"} unless current
      return {"status" => "not_compared", "reason" => "no_previous_benchmark"} unless previous
      environments = [current, previous].map { |entry| entry["environment"] }
      complete = environments.all? do |environment|
        environment.is_a?(Hash) && (BENCH_ENVIRONMENT - environment.keys).empty? &&
          (BENCH_ENVIRONMENT - %w[cpus writes_only]).all? { |key| environment[key].is_a?(String) && !environment[key].empty? } &&
          environment["cpus"].is_a?(Integer) && environment["cpus"] > 0 && [true, false].include?(environment["writes_only"])
      end
      return {"status" => "not_compared", "reason" => "unknown_environment"} unless complete
      return {"status" => "not_compared", "reason" => "environment_changed", "before_environment" => environments.last, "after_environment" => environments.first} unless environments.first == environments.last
      valid = [current, previous].all? do |entry|
        entry["samples"].is_a?(Array) && !entry["samples"].empty? && entry["samples"].all? do |sample|
          sample.is_a?(Hash) && METRICS.all? { |key| sample[key].is_a?(Numeric) && sample[key].finite? && sample[key] >= 0 }
        end
      end
      return {"status" => "not_compared", "reason" => "invalid_samples"} unless valid
      changes = METRICS.to_h do |key|
        old = previous["samples"].sum { |sample| sample.fetch(key) }.fdiv(previous["samples"].size)
        fresh = current["samples"].sum { |sample| sample.fetch(key) }.fdiv(current["samples"].size)
        [key, {"before" => old, "after" => fresh, "delta" => fresh - old}]
      end
      {"status" => "compared", "environment" => environments.first, "changes" => changes,
       "before_samples" => previous["samples"].size, "after_samples" => current["samples"].size,
       "limitation" => "Sample means only; no calibrated performance threshold or pass/fail gate."}
    end
  end
end
