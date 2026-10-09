# frozen_string_literal: true

require "bundler"
require "bundler/plugin/api"
require_relative "capability_lock"
require_relative "result_store"

module Bonebed
  class BundlerPlugin
    class Rejected < Bundler::BundlerError; end

    def self.register!
      api = Bundler::Plugin::API.new
      checker = nil
      Bundler::Plugin::API.hook("before-install-all") do |_dependencies|
        checker = nil
        raise Rejected, "Bonebed requires BUNDLE_FROZEN=true before bundle install" unless api.frozen_bundle?

        root = api.root.to_s
        path = ->(key, default) { File.expand_path(ENV.fetch(key, default), root) }
        policy = path.call("BONEBED_PLUGIN_POLICY", ".bonebed.yml")
        policy = nil unless ENV.key?("BONEBED_PLUGIN_POLICY") || File.exist?(policy)
        candidate = new(lockfile: api.default_lockfile.to_s,
          results_dir: path.call("BONEBED_PLUGIN_RESULTS", "results"),
          approval_path: path.call("BONEBED_PLUGIN_LOCK", "Gemfile.capabilities.lock"), policy_path: policy)
        count = candidate.check!
        checker = candidate
        api.ui.info "Bonebed approved #{count} locked package observations."
      end
      Bundler::Plugin::API.hook("before-install") do |installation|
        raise Rejected, "Bonebed install has no approved preflight" unless checker

        checker.check_spec!(installation.spec)
      end
    end

    def initialize(lockfile:, results_dir:, approval_path:, policy_path: nil)
      @lockfile, @results_dir, @approval_path, @policy_path = lockfile, results_dir, approval_path, policy_path
      @approved = []
    end

    def check!
      @approved = []
      raise Rejected, "Bonebed results directory is missing" unless Dir.exist?(@results_dir)

      approved = CapabilityLock.load(@approval_path)
      policy = Policy.load(@policy_path)
      contents = File.read(@lockfile)
      raise Rejected, "Bonebed requires a nonempty Gemfile.lock" if contents.strip.empty?
      raise Rejected, "Bonebed unsupported source section in Gemfile.lock" if contents.match?(/^(?:PATH|GIT|PLUGIN SOURCE)\r?$/)

      lock = Bundler::LockfileParser.new(contents)
      lock.specs.each { |spec| validate_source!(spec) }
      manifests = read_observations
      specs = lock.specs.select { |spec| Gem::Platform.match_gem?(spec.platform, spec.name) }
      specs.each { |spec| validate_observations!(spec, approved, policy, manifests) }
      @approved = specs.map { |spec| identity(spec) }
      @approved.size
    rescue ArgumentError, KeyError, SystemCallError => error
      raise Rejected, "Bonebed check failed: #{error.message}"
    end

    def check_spec!(spec)
      # Bundler emits an install hook for its already-running metadata specification as well.
      return true if spec.name == "bundler" && spec.version.to_s == Bundler::VERSION && spec.source.is_a?(Bundler::Source::Metadata)

      raise Rejected, "Bonebed package is not approved: #{identity(spec).inspect}" unless @approved.include?(identity(spec))

      validate_source!(spec)
      true
    end

    private

    def identity(spec)
      [spec.name, spec.version.to_s, spec.platform.to_s]
    end

    def read_observations
      index = {}
      ResultStore.paths(@results_dir).each do |path|
        manifest = JSON.parse(File.read(path))
        raise Rejected, "Bonebed invalid observation structure: #{path.inspect}" unless ResultStore.valid?(manifest)

        CapabilityKeys.call(manifest)
        key = ResultStore.identity(manifest)
        rank = [manifest.fetch("schema_version", 1), File.mtime(path)]
        previous = index[key]
        index[key] = [rank, manifest] unless previous && (rank <=> previous.first) <= 0
      rescue JSON::ParserError
        raise Rejected, "Bonebed invalid observation JSON: #{path.inspect}"
      end
      index.values.map(&:last)
    end

    def validate_source!(spec)
      source = spec.source if spec.respond_to?(:source)
      unless source.is_a?(Bundler::Source::Rubygems) && !source.remotes.empty? &&
          source.remotes.all? { |remote| %w[https://rubygems.org https://rubygems.org/].include?(remote.to_s) }
        raise Rejected, "Bonebed unsupported source for #{spec.name.inspect}; only https://rubygems.org is supported"
      end
    end

    def validate_observations!(spec, approved, policy, manifests)
      name, version, platform = identity(spec)
      entry = approved.fetch("gems")[name]
      raise Rejected, "Bonebed missing approval for #{name.inspect}" unless entry
      raise Rejected, "Bonebed approval version differs for #{name.inspect}" unless entry.fetch("version") == version

      observations = manifests.select { |manifest| manifest.fetch("gem").values_at("name", "version", "platform") == [name, version, platform] }
      phases = %w[install require]
      phases << "plugin" if observations.any? { |manifest| manifest.dig("gem", "rubygems_plugin") }
      phases.each do |phase|
        keys = entry.fetch("phases")[phase]
        raise Rejected, "Bonebed missing #{phase} approval for #{name.inspect}" unless keys

        samples = observations.select { |manifest| manifest.fetch("phase") == phase }
        raise Rejected, "Bonebed #{name.inspect} #{phase} is unobserved for version #{version.inspect} platform #{platform.inspect}" if samples.empty?

        samples.each do |manifest|
          validate_complete!(manifest, samples)
          additions = CapabilityKeys.call(manifest) - keys
          raise Rejected, "Bonebed unapproved capabilities for #{name.inspect} #{phase}: #{additions.inspect}" unless additions.empty?

          violations = policy.violations(manifest)
          raise Rejected, "Bonebed policy violations for #{name.inspect} #{phase}: #{violations.map { |finding| finding.fetch("rule_id") }.inspect}" unless violations.empty?
        end
      end
    end

    def validate_complete!(manifest, samples)
      complete = manifest["schema_version"] == 2 && manifest.fetch("errors").empty? && manifest["observer_errors"] == [] &&
        manifest.dig("target", "exit_status") == 0 && manifest.dig("target", "timed_out") == false && manifest.dig("target", "signal").nil? &&
        manifest.dig("run", "mode", "writes_only") == false
      complete &&= repeat_complete?(manifest, samples)
      raise Rejected, "Bonebed incomplete observation for #{manifest.dig("gem", "name").inspect} #{manifest.fetch("phase")}" unless complete
    end

    def repeat_complete?(manifest, samples)
      mode = manifest.dig("run", "mode")
      count = mode.fetch("repeat", 1)
      repetition = manifest.dig("run", "repeat")
      return repetition.nil? if count == 1
      return false unless repetition && repetition["count"] == count

      group = samples.select do |sample|
        sample.dig("run", "repeat", "group") == repetition.fetch("group") &&
          sample.dig("gem", "require_path") == manifest.dig("gem", "require_path") &&
          ResultStore.mode_identity(sample.dig("run", "mode")) == ResultStore.mode_identity(mode)
      end
      group.map { |sample| sample.dig("run", "repeat", "index") }.sort == (1..count).to_a && group.all? do |sample|
        stability = sample["stability"]
        sample.dig("run", "repeat", "count") == count && stability.is_a?(Hash) &&
          stability["complete"] == true && stability["samples"] == count
      end
    end
  end
end
