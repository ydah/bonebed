# frozen_string_literal: true

require "json"
require "rbconfig"
require "rubygems/package"
require "rubygems/stub_specification"
require "bundler"
require "securerandom"
require "time"
require_relative "baseline"
require_relative "prefetcher"
require_relative "gem_environment"
require_relative "manifest_builder"
require_relative "result_store"
require_relative "phase/install"
require_relative "phase/require"

module Bonebed
  class Dig
    PHASES = %w[require install all].freeze
    attr_reader :results_dir, :last_errors, :last_observer_errors

    def initialize(results_dir: "results", timeout: nil, offline: false, baseline: Baseline.new,
      output_limit: Session::OUTPUT_LIMIT, argv_limit: 64, quiet_target: false,
      prefetcher: Prefetcher.new, real_home: false, cwd: nil)
      raise ArgumentError, "timeout must be positive" if timeout && !(timeout.is_a?(Numeric) && timeout.positive?)
      raise ArgumentError, "output limit must be nonnegative" unless output_limit.is_a?(Integer) && output_limit >= 0
      raise ArgumentError, "argv limit must be positive" unless argv_limit.is_a?(Integer) && argv_limit.positive?

      @session_options = {output_limit:, argv_limit:, quiet_target:, target_stdout: $stderr, offline:}
      @results_dir = results_dir
      @store = ResultStore.new(results_dir)
      @timeout = timeout
      @offline = offline
      @baseline = baseline
      @prefetcher = prefetcher
      @environment_options = {real_home:, cwd:}
      @last_errors = []
      @last_observer_errors = []
    end

    def run(name, phase: "require", version: nil, require_path: nil, platform: nil)
      validate!(name, phase, version, require_path:)
      @last_errors = []
      @last_observer_errors = []
      @run = {"id" => SecureRandom.uuid, "started_at" => Time.now.utc.iso8601,
              "mode" => {"offline" => @offline, "honeypot" => true}}
      paths = Bundler.with_unbundled_env do
        Bundler.reset!
        Gem::Specification.reset
        GemEnvironment.open(**@environment_options) do |environment|
          if phase == "require"
            specification = Gem::Specification.find_by_name(name, version ? "=#{version}" : Gem::Requirement.default)
            specifications = environment.copy_gems(specification)
            [observe_require(environment, specification, specifications, require_path)]
          else
            packages = @prefetcher.call(name, version, platform:)
            packages = packages.map do |source|
              destination = File.join(environment.prefetch, File.basename(source))
              FileUtils.copy_file(source, destination)
              destination
            end
            specifications = packages.map { |path| Gem::Package.new(path).spec }
            specification = specifications.find { |spec| spec.name == name }
            raise Error, "resolved packages do not include #{name}" unless specification

            package = packages.fetch(specifications.index(specification))
            baseline = @baseline.capture(phase: "install")
            collector = Phase::Install.call(environment, packages, **session_options("install"))
            manifest = build(environment, specification, "install", collector.snapshot(environment.normalizer), baseline, specifications:, package:)
            output = [save(manifest)]
            if phase == "all" && manifest.fetch("errors").empty?
              specification.loaded_from = File.join(environment.gem_home, "specifications", "#{specification.full_name}.gemspec")
              output << observe_require(environment, specification, specifications, require_path, package:)
            end
            output
          end
        end
      end
      (phase == "all") ? paths : paths.first
    rescue Prefetcher::Error => error
      @last_errors = [error.message]
      path = write_failure(name, phase: (phase == "all") ? "install" : phase, version: version || "unknown", error:)
      (phase == "all") ? [path] : path
    end

    def write_failure(name, phase:, version:, error:)
      validate!(name, phase)
      observation = empty_observation(error)
      data = ManifestBuilder.call(name, version, phase, observation, Baseline::Result.new(id: nil, observation: empty_observation), run: @run)
      data["failure_reason"] = error.is_a?(Prefetcher::Error) ? "prefetch_failed" : "setup_failed"
      @store.write(data)
    end

    def result_exists?(name, phase:, version: nil, require_path: nil, platform: nil)
      validate!(name, phase, version, require_path:)
      phases = (phase == "all") ? %w[install require] : [phase]
      phases.all? { |entry| @store.exists?(name, phase: entry, version:, require_path: (entry == "install") ? nil : require_path, platform:) }
    end

    private

    def validate!(name, phase, version = nil, require_path: nil)
      raise ArgumentError, "invalid gem name" unless name.is_a?(String) && name.match?(Gem::Specification::VALID_NAME_PATTERN) && name.match?(/[a-zA-Z]/) && !name.start_with?(".", "-", "_")
      raise ArgumentError, "phase must be require, install or all" unless PHASES.include?(phase)
      raise ArgumentError, "invalid gem version" if version && !Gem::Version.correct?(version)
      raise ArgumentError, "require path must not be empty" if require_path == ""
      raise ArgumentError, "require path only applies to require or all phase" if require_path && phase == "install"
    end

    def session_options(phase)
      @session_options.merge(timeout: @timeout || ((phase == "install") ? 600 : 60))
    end

    def observe_require(environment, specification, specifications, require_path, package: nil)
      baseline = @baseline.capture(phase: "require")
      begin
        collector, require_path = Phase::Require.call(environment, specification, require_path:, **session_options("require"))
        observation = collector.snapshot(environment.normalizer)
      rescue Gem::LoadError => error
        observation = empty_observation(error)
      end
      save(build(environment, specification, "require", observation, baseline, specifications:, package:, require_path:))
    end

    def build(environment, specification, phase, observation, baseline, **options)
      data = ManifestBuilder.call(specification.name, specification.version.to_s, phase, observation, baseline,
        platform: specification.platform.to_s, run: @run, **options)
      data["failure_reason"] = if observation.dig(:target, :timed_out)
        "timeout"
      elsif observation.dig(:target, :signal)
        "signal"
      elsif !observation.fetch(:errors).empty?
        (phase == "install") ? "build_failed" : "require_failed"
      end
      environment.honeypot ? environment.honeypot.redact(data) : data
    end

    def save(manifest)
      @last_errors.concat(manifest.fetch("errors"))
      @last_observer_errors.concat(manifest.fetch("observer_errors"))
      @store.write(manifest)
    end

    def empty_observation(error = nil)
      {files: {read: {}, write: {}}, network: {}, exec: {}, threads: {},
       stats: {openat_total: 0, notify_roundtrips: 0, wall_ms: 0},
       errors: error ? ["#{error.class}: #{error.message}"] : [], observer_errors: [], stdout: "", stderr: ""}
    end
  end
end
