# frozen_string_literal: true

require "uri"
require_relative "policy"

module Bonebed
  module Sarif
    LEVELS = {"critical" => "error", "high" => "error", "medium" => "warning", "low" => "note", "info" => "note"}.freeze
    SCORES = {"critical" => "9.0", "high" => "8.0", "medium" => "5.0", "low" => "2.0", "info" => "0.0"}.freeze

    module_function

    def call(manifests, policy: nil, lockfile: nil, source_root: Dir.pwd)
      raise ArgumentError, "SARIF manifests must be an array" unless manifests.is_a?(Array)

      uri = artifact_uri(lockfile, source_root) if lockfile
      lines = lockfile ? File.readlines(lockfile, chomp: true) : []
      rules = {}
      results = manifests.flat_map do |manifest|
        findings = policy ? policy.findings(manifest) : manifest.fetch("findings") { Policy.new.findings(manifest) }
        raise ArgumentError, "SARIF findings must be an array" unless findings.is_a?(Array)

        findings.each { |finding| validate_finding!(finding) }
        findings.reject { |finding| finding["allowed"] }.map do |finding|
          id = finding.fetch("rule_id")
          severity = finding.fetch("severity")
          rules[id] ||= {"id" => id, "shortDescription" => {"text" => finding.fetch("message")},
                         "properties" => {"security-severity" => SCORES.fetch(severity)}}
          reference = finding.fetch("references", []).first
          rules[id]["helpUri"] = reference if reference
          gem = manifest.fetch("gem")
          result = {"ruleId" => id, "level" => LEVELS.fetch(severity),
                    "message" => {"text" => "#{gem.fetch("name")} #{gem.fetch("version")} (#{manifest.fetch("phase")}): #{finding.fetch("message")} — #{finding.fetch("capability")}"},
                    "properties" => {"capability" => finding.fetch("capability"), "phase" => manifest.fetch("phase")}}
          line = lines.index { |text| text.match?(/\A    #{Regexp.escape(gem.fetch("name"))} \(#{Regexp.escape(gem.fetch("version"))}(?:-[^)]+)?\)\z/) }
          if line
            result["locations"] = [{"physicalLocation" => {"artifactLocation" => {"uri" => uri}, "region" => {"startLine" => line + 1}}}]
          end
          result
        end
      end
      {"$schema" => "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json", "version" => "2.1.0",
       "runs" => [{"tool" => {"driver" => {"name" => "bonebed", "version" => VERSION, "rules" => rules.values}}, "results" => results}]}
    end

    def validate_finding!(finding)
      valid = finding.is_a?(Hash) && %w[rule_id severity message capability].all? { |key| finding[key].is_a?(String) && !finding[key].empty? }
      raise ArgumentError, "invalid SARIF finding" unless valid && LEVELS.key?(finding["severity"]) && [true, false].include?(finding.fetch("allowed", false))

      references = finding.fetch("references", [])
      raise ArgumentError, "invalid SARIF references" unless references.is_a?(Array) && references.all? { |url| url.is_a?(String) }

      references.each do |url|
        parsed = URI.parse(url)
        raise ArgumentError, "SARIF reference must be an HTTP(S) URL" unless %w[http https].include?(parsed.scheme) && parsed.host
      end
    rescue URI::InvalidURIError => error
      raise ArgumentError, "invalid SARIF reference: #{error.message}"
    end

    def artifact_uri(path, root)
      relative = Pathname.new(File.expand_path(path)).relative_path_from(Pathname.new(File.expand_path(root))).to_s
      raise ArgumentError, "SARIF lockfile must be inside the source root" if relative == ".." || relative.start_with?("../")

      URI::DEFAULT_PARSER.escape(relative)
    end
  end
end
