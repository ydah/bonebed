# frozen_string_literal: true

require_relative "policy"

module Bonebed
  module CapabilityLock
    def self.load(path)
      data = Policy.read_yaml(path)
      raise ArgumentError, "invalid capability lock" unless data.is_a?(Hash) && data["version"] == 1 && data["gems"].is_a?(Hash) && (data.keys - %w[version gems]).empty?

      data.fetch("gems").each do |name, entry|
        valid = name.is_a?(String) && entry.is_a?(Hash) && entry["version"].is_a?(String) && entry["phases"].is_a?(Hash) && (entry.keys - %w[version phases]).empty?
        raise ArgumentError, "invalid capability lock gem" unless valid

        entry.fetch("phases").each do |phase, keys|
          raise ArgumentError, "invalid capability lock phase" unless %w[install require plugin exec].include?(phase) && keys.is_a?(Array) && keys.all? { |key| key.is_a?(String) && !key.empty? }
        end
      end
      data
    end
  end
end
