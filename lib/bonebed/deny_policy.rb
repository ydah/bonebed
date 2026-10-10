# frozen_string_literal: true

require "digest"
require "json"
require_relative "policy"
require_relative "path_normalizer"

module Bonebed
  # A decision about copied syscall arguments, never a filesystem or network boundary.
  class DenyPolicy
    def self.load(path)
      config = Policy.read_yaml(path)
      Policy.new(config)
      config
    end

    def self.context(config, name:, phase:, environment: nil)
      context = {"config" => config, "name" => name, "phase" => phase}
      environment ? in_environment(context, environment) : context
    end

    def self.in_environment(context, environment)
      context.merge("normalization" => {"home" => environment.home, "cwd" => environment.project,
                                        "tmpdir" => environment.root, "gem_paths" => [environment.gem_home, *Gem.path]})
    end

    def self.digest(config)
      Digest::SHA256.hexdigest(JSON.generate(config))
    end

    def initialize(context, normalizer:)
      unless context.is_a?(Hash) && (context.keys - %w[config name phase normalization]).empty? && context.key?("config") &&
          context["name"].is_a?(String) && !context["name"].empty? && (Policy::PHASES - %w[all *]).include?(context["phase"])
        raise ArgumentError, "invalid deny policy context"
      end
      @policy = Policy.new(context.fetch("config"))
      @base = {"schema_version" => 2, "gem" => {"name" => context.fetch("name")}, "phase" => context.fetch("phase")}
      @normalizer = normalizer
      if context.key?("normalization")
        paths = context.fetch("normalization")
        valid = paths.is_a?(Hash) && paths.keys.sort == %w[cwd gem_paths home tmpdir] &&
          %w[cwd home tmpdir].all? { |key| paths[key].is_a?(String) } && paths["gem_paths"].is_a?(Array) && paths["gem_paths"].all? { |path| path.is_a?(String) }
        raise ArgumentError, "invalid deny normalization" unless valid
        @normalizer = PathNormalizer.new(**paths.transform_keys(&:to_sym))
      end
    end

    def violations(field, event)
      normalized = event.to_h do |key, value|
        value = @normalizer.call(value) if %i[path from to].include?(key.to_sym) && value.is_a?(String) && !(key.to_sym == :from && event[:symbolic])
        [key.to_s, value]
      end
      fields = case field
      when :files
        {"files" => {normalized.fetch("mode").to_s => [normalized.fetch("path")]}}
      when :changes
        {"files" => {normalized.fetch("operation").to_s => [normalized.except("operation")]}}
      else
        {field.to_s => [normalized]}
      end
      @policy.violations(@base.merge(fields))
    end
  end
end
