# frozen_string_literal: true

require_relative "../policy"

module Bonebed
  module Formatter
    module Tabular
      HEADERS = %w[gem version phase capability rule severity allowed].freeze

      def self.entries(manifests, policy: nil)
        default_policy = policy || Policy.new
        manifests.map do |manifest|
          findings = policy ? policy.findings(manifest) : manifest.fetch("findings") { default_policy.findings(manifest) }
          [manifest, findings]
        end
      end

      def self.severity(finding)
        Policy::SEVERITIES.index(finding["severity"]) || -1
      end

      def self.rows(entries)
        entries.flat_map do |manifest, findings|
          findings = [{"capability" => "none", "severity" => "", "rule_id" => "", "allowed" => false}] if findings.empty?
          findings.map { |finding| [manifest, finding] }
        end.sort_by do |manifest, finding|
          [-severity(finding), manifest.dig("gem", "name").to_s, manifest.dig("gem", "version").to_s,
            manifest["phase"].to_s, finding["rule_id"].to_s, finding["capability"].to_s]
        end.map do |manifest, finding|
          [manifest.dig("gem", "name"), manifest.dig("gem", "version"), manifest["phase"],
            finding["capability"], finding["rule_id"], finding["severity"], finding["allowed"]]
        end
      end
    end
  end
end
