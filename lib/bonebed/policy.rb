# frozen_string_literal: true

require "yaml"
require "uri"
require_relative "capability_keys"

module Bonebed
  class Policy
    SEVERITIES = %w[info low medium high critical].freeze
    PHASES = %w[install require plugin bundler_plugin exec all *].freeze
    DEFAULT_RULES = File.expand_path("rules/default.yml", __dir__)
    attr_reader :defaults, :rules

    def self.load(path = nil)
      new(path ? read_yaml(path) : {})
    end

    def self.read_yaml(path)
      YAML.safe_load_file(path, permitted_classes: [], permitted_symbols: [], aliases: false)
    rescue Psych::Exception => error
      raise ArgumentError, "invalid policy YAML: #{error.message}"
    end

    def initialize(config = {})
      mapping!(config, %w[version defaults rules allow], "policy")
      raise ArgumentError, "policy version must be 1" unless config.fetch("version", 1) == 1

      @defaults = {"fail_on" => "high"}.merge(mapping!(config.fetch("defaults", {}), %w[phase env_profile offline fail_on verbose require_container allow_host top_fallback], "defaults"))
      severity!(@defaults.fetch("fail_on"))
      raise ArgumentError, "invalid default phase" if @defaults.key?("phase") && !PHASES.include?(@defaults["phase"])
      raise ArgumentError, "invalid environment profile" if @defaults.key?("env_profile") && !%w[ci dev prod].include?(@defaults["env_profile"])
      raise ArgumentError, "offline must be boolean" if @defaults.key?("offline") && ![true, false].include?(@defaults["offline"])
      string!(@defaults["top_fallback"], "top_fallback") if @defaults.key?("top_fallback")
      %w[verbose require_container allow_host].each do |key|
        raise ArgumentError, "#{key} must be boolean" if @defaults.key?(key) && ![true, false].include?(@defaults[key])
      end

      configuration = mapping!(config.fetch("rules", {}), %w[extends disable custom], "rules")
      raise ArgumentError, "rules extends must be default" unless configuration.fetch("extends", "default") == "default"

      defaults = self.class.read_yaml(DEFAULT_RULES).map { |rule| validate_rule(rule) }
      custom = configuration.fetch("custom", [])
      raise ArgumentError, "custom rules must be an array" unless custom.is_a?(Array)

      custom = custom.map { |rule| validate_rule(rule) }
      raise ArgumentError, "duplicate custom rule ID" unless custom.map { |rule| rule["id"] }.uniq.size == custom.size

      by_id = (defaults + custom).to_h { |rule| [rule.fetch("id"), rule] }
      disabled = strings!(configuration.fetch("disable", []), "disabled rules")
      raise ArgumentError, "unknown disabled rule" unless (disabled - by_id.keys).empty?

      @rules = by_id.except(*disabled).values
      @allow = config.fetch("allow", {})
      raise ArgumentError, "allow must be an object" unless @allow.is_a?(Hash)

      @allow.each do |gem, phases|
        string!(gem, "gem pattern")
        mapping!(phases, PHASES, "allowed phases")
        phases.each_value { |patterns| strings!(patterns, "allowed capabilities") }
      end
    end

    def findings(manifest, keys: CapabilityKeys.call(manifest))
      name = string!(manifest.dig("gem", "name"), "manifest gem name")
      phase = string!(manifest["phase"], "manifest phase")
      raise ArgumentError, "invalid manifest phase" unless (PHASES - %w[all *]).include?(phase)

      @rules.flat_map do |rule|
        next [] if rule["phase"] && !(rule["phase"] & [phase, "all", "*"]).any?

        keys.filter_map do |key|
          next unless rule.fetch("match").any? { |pattern| matches?(pattern, key) }

          {"rule_id" => rule.fetch("id"), "severity" => rule.fetch("severity"),
           "message" => rule.fetch("message", rule.fetch("id")), "capability" => key,
           "allowed" => allowed?(name, phase, key), "references" => rule.fetch("references", [])}
        end
      end.sort_by { |finding| [-SEVERITIES.index(finding.fetch("severity")), finding.fetch("rule_id"), finding.fetch("capability")] }
    end

    def violations(manifest, fail_on: nil)
      threshold = SEVERITIES.index(severity!(fail_on || @defaults.fetch("fail_on")))
      findings(manifest).reject { |finding| finding["allowed"] || SEVERITIES.index(finding.fetch("severity")) < threshold }
    end

    private

    def allowed?(name, phase, key)
      @allow.any? do |pattern, phases|
        matches?(pattern, name) && phases.any? do |allowed_phase, patterns|
          [phase, "all", "*"].include?(allowed_phase) && patterns.any? { |capability| matches?(capability, key) }
        end
      end
    end

    def matches?(pattern, value)
      File.fnmatch?(pattern, value, File::FNM_DOTMATCH | File::FNM_EXTGLOB)
    end

    def validate_rule(rule)
      mapping!(rule, %w[id severity phase match message references], "rule")
      id = string!(rule["id"], "rule ID")
      raise ArgumentError, "invalid rule ID" unless id.match?(/\A[a-zA-Z0-9][a-zA-Z0-9_-]*\z/)

      severity!(rule["severity"])
      patterns = strings!(rule["match"], "rule match")
      raise ArgumentError, "rule match must not be empty" if patterns.empty?
      if rule.key?("phase")
        phases = strings!(rule["phase"], "rule phase")
        raise ArgumentError, "invalid rule phase" if phases.empty? || !(phases - PHASES).empty?
      end
      string!(rule["message"], "rule message") if rule.key?("message")
      strings!(rule.fetch("references", []), "rule references").each do |url|
        parsed = URI.parse(url)
        raise ArgumentError, "rule reference must be an HTTP(S) URL" unless %w[http https].include?(parsed.scheme) && parsed.host
      end
      rule
    rescue URI::InvalidURIError => error
      raise ArgumentError, "invalid rule reference: #{error.message}"
    end

    def mapping!(value, fields, label)
      raise ArgumentError, "#{label} must be an object" unless value.is_a?(Hash)
      raise ArgumentError, "unknown #{label} field" unless (value.keys - fields).empty?

      value
    end

    def string!(value, label)
      raise ArgumentError, "#{label} must be a nonempty string" unless value.is_a?(String) && !value.empty?

      value
    end

    def strings!(value, label)
      raise ArgumentError, "#{label} must be an array of strings" unless value.is_a?(Array)

      value.each { |entry| string!(entry, label) }
    end

    def severity!(value)
      raise ArgumentError, "invalid severity: #{value.inspect}" unless SEVERITIES.include?(value)

      value
    end
  end
end
