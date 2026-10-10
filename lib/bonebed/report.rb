# frozen_string_literal: true

require "json"
require_relative "formatter/markdown"
require_relative "result_store"

module Bonebed
  class Report
    def self.summary(directory)
      raise ArgumentError, "results directory does not exist: #{directory}" unless Dir.exist?(directory)

      totals = {"manifests" => 0, "successful" => 0, "target_failures" => 0, "observer_failures" => 0,
                "phases" => Hash.new(0), "capabilities" => {}}
      ResultStore.each(directory) do |manifest|
        totals["manifests"] += 1
        totals["target_failures"] += 1 if target_failed?(manifest)
        totals["successful"] += 1 if successful?(manifest)
        totals["observer_failures"] += 1 unless Array(manifest["observer_errors"]).empty?
        totals["phases"][manifest.fetch("phase")] += 1
        flags = ResultStore.capabilities(manifest).merge(manifest["capabilities"] || {})
        flags.each do |key, value|
          counts = totals["capabilities"][key] ||= {"observed" => 0, "not_observed" => 0, "unknown" => 0}
          counts[{true => "observed", false => "not_observed"}.fetch(value, "unknown")] += 1
        end
      end
      totals
    end

    def self.target_failed?(manifest)
      !manifest.fetch("errors", []).empty? || manifest.dig("target", "timed_out") ||
        manifest.dig("target", "signal") || ![nil, 0].include?(manifest.dig("target", "exit_status"))
    end

    def self.successful?(manifest)
      manifest["failure_reason"] != "observation_failed" && !target_failed?(manifest)
    end

    def initialize(directory)
      raise ArgumentError, "results directory does not exist: #{directory}" unless Dir.exist?(directory)

      @manifests = ResultStore.read(directory)
    end

    def markdown
      successful = @manifests.select { |manifest| self.class.successful?(manifest) }
      failed = @manifests.select { |manifest| self.class.target_failed?(manifest) }
      Formatter::Markdown.new(@manifests, policy: Policy.new).survey(successful:, failed:)
    end
  end
end
