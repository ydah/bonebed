# frozen_string_literal: true

module Bonebed
  module Difference
    module_function

    def call(observed, baseline)
      files = observed.fetch(:files).to_h do |mode, entries|
        [mode, subtract(entries, baseline.dig(:files, mode) || {})]
      end
      {
        files:,
        network: subtract(observed.fetch(:network), baseline.fetch(:network, {})),
        exec: subtract(observed.fetch(:exec), baseline.fetch(:exec, {})),
        stats: observed.fetch(:stats).merge(openat_after_baseline: files.values.sum { |entries| entries.values.sum }),
        errors: observed.fetch(:errors)
      }
    end

    def subtract(observed, baseline)
      observed.each_with_object({}) do |(event, count), result|
        remaining = count - baseline.fetch(event, 0)
        result[event] = remaining if remaining.positive?
      end
    end
    private_class_method :subtract
  end
end
