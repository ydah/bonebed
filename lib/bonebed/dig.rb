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
require_relative "phase/plugin"
require_relative "phase/executable"
require_relative "policy"
require_relative "enforcement"
require_relative "capability_keys"

module Bonebed
  class Dig
    PHASES = %w[require install plugin exec all].freeze
    attr_reader :results_dir, :last_errors, :last_observer_errors

    def initialize(results_dir: "results", timeout: nil, offline: false, baseline: Baseline.new,
      output_limit: Session::OUTPUT_LIMIT, argv_limit: 64, quiet_target: false,
      prefetcher: Prefetcher.new, real_home: false, cwd: nil, env_profile: "dev", writes_only: false, enforce: nil, trace: nil, repeat: 1)
      raise ArgumentError, "timeout must be positive" if timeout && !(timeout.is_a?(Numeric) && timeout.positive?)
      raise ArgumentError, "output limit must be nonnegative" unless output_limit.is_a?(Integer) && output_limit >= 0
      raise ArgumentError, "argv limit must be positive" unless argv_limit.is_a?(Integer) && argv_limit.positive?
      raise ArgumentError, "repeat must be an integer from 1 to 100" unless repeat.is_a?(Integer) && (1..100).cover?(repeat)

      @repeat = repeat
      raise ArgumentError, "invalid environment profile" unless %w[ci dev prod].include?(env_profile)

      @env_profile = env_profile
      @enforce = enforce
      @trace = trace
      @session_options = {output_limit:, argv_limit:, quiet_target:, target_stdout: $stderr, offline:, writes_only:}
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

    def run(name, phase: "require", version: nil, require_path: nil, platform: nil, executable: nil, arguments: [])
      validate_invocation!(phase, executable, arguments)
      return run_once(name, phase:, version:, require_path:, platform:, executable:, arguments:) if @repeat == 1

      group = SecureRandom.uuid
      errors = []
      observer_errors = []
      paths = @repeat.times.flat_map do |index|
        @repeat_metadata = {"group" => group, "index" => index + 1, "count" => @repeat}
        samples = Array(run_once(name, phase:, version:, require_path:, platform:, executable:, arguments:))
        errors.concat(@last_errors)
        observer_errors.concat(@last_observer_errors)
        sample = ResultStore.load(samples.first)
        if sample && sample.dig("gem", "version") != "unknown"
          version ||= sample.dig("gem", "version")
          platform ||= sample.dig("gem", "platform")
        end
        samples
      end
      annotate_stability(paths)
      @last_errors = errors
      @last_observer_errors = observer_errors
      paths
    ensure
      @repeat_metadata = nil
    end

    def run_once(name, phase:, version:, require_path:, platform:, executable:, arguments:)
      validate!(name, phase, version, require_path:)
      @last_errors = []
      @last_observer_errors = []
      @run = {"id" => SecureRandom.uuid, "started_at" => Time.now.utc.iso8601,
              "mode" => observation_mode}
      @run["repeat"] = @repeat_metadata if @repeat_metadata
      paths = Bundler.with_unbundled_env do
        Bundler.reset!
        Gem::Specification.reset
        GemEnvironment.open(**@environment_options) do |environment|
          @session_options[:enforcement] = Enforcement.load(@enforce, environment) if @enforce
          environment.env.merge!({"CI" => "true", "GITHUB_ACTIONS" => "true", "GITHUB_REPOSITORY" => "example/app"}) if @env_profile == "ci"
          environment.env.merge!({"RAILS_ENV" => "production", "RACK_ENV" => "production"}) if @env_profile == "prod"
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

            if phase == "exec"
              executable = Phase::Executable.select(specification, executable)
              @run["executable"] = executable
              @run["arguments"] = arguments
            end
            package = packages.fetch(specifications.index(specification))
            baseline = @baseline.capture(phase: "install", **baseline_options)
            collector = Phase::Install.call(environment, packages, **session_options("install", specification, environment))
            manifest = build(environment, specification, "install", collector.snapshot(environment.normalizer), baseline, specifications:, package:)
            output = [save(manifest)]
            if phase == "exec" && manifest.fetch("errors").empty?
              baseline = @baseline.capture(phase: "require", **baseline_options)
              collector = Phase::Executable.call(environment, specification, executable:, arguments:,
                **session_options("exec", specification, environment))
              result = build(environment, specification, "exec", collector.snapshot(environment.normalizer), baseline, specifications:, package:)
              normalizer = environment.normalizer
              result["command"] = Phase::Executable.command(environment, executable, arguments).map { |arg| normalizer.scrub(arg) }
              output << save(result)
            end
            if manifest.fetch("errors").empty? && (phase == "plugin" || (phase == "all" && manifest.dig("gem", "rubygems_plugin")))
              baseline = @baseline.capture(phase: "plugin", **baseline_options)
              plugin = Phase::Plugin.call(environment, **session_options("plugin", specification, environment))
              output << save(build(environment, specification, "plugin", plugin.snapshot(environment.normalizer), baseline, specifications:, package:))
            end
            if phase == "all" && manifest.fetch("errors").empty?
              specification.loaded_from = File.join(environment.gem_home, "specifications", "#{specification.full_name}.gemspec")
              output << observe_require(environment, specification, specifications, require_path, package:)
            end
            output
          end
        end
      end
      (phase == "all") ? paths : paths.last
    rescue Prefetcher::Error => error
      @last_errors = [error.message]
      path = write_failure(name, phase: (phase == "all") ? "install" : phase, version: version || "unknown", error:)
      (phase == "all") ? [path] : path
    end
    private :run_once

    def write_failure(name, phase:, version:, error:)
      validate!(name, phase)
      observation = empty_observation(error)
      data = ManifestBuilder.call(name, version, phase, observation, Baseline::Result.new(id: nil, observation: empty_observation), run: @run)
      data["failure_reason"] = error.is_a?(Prefetcher::Error) ? "prefetch_failed" : "setup_failed"
      @store.write(data)
    end

    def result_exists?(name, phase:, version: nil, require_path: nil, platform: nil, executable: nil, arguments: [])
      validate_invocation!(phase, executable, arguments)
      validate!(name, phase, version, require_path:)
      mode = observation_mode
      if phase == "exec"
        return @store.matching(name, phase:, version:, platform:, mode:, executable:, arguments:).any? do |manifest|
          executable || manifest.dig("gem", "executables") == [manifest.dig("run", "executable")]
        end
      end
      return @store.exists?(name, phase:, version:, require_path:, platform:, mode:) unless phase == "all"

      @store.matching(name, phase: "install", version:, platform:, mode:).any? do |installed|
        gem = installed.fetch("gem")
        phases = gem["rubygems_plugin"] ? %w[require plugin] : %w[require]
        phases.all? do |entry|
          @store.matching(name, phase: entry, version: gem.fetch("version"), platform: gem["platform"],
            require_path: (entry == "require") ? require_path : nil, mode:).any? do |sample|
            @repeat == 1 || sample.dig("run", "repeat", "group") == installed.dig("run", "repeat", "group")
          end
        end
      end
    end

    def prepare_baselines(phase:)
      phases = case phase
      when "all" then %w[install require plugin]
      when "exec" then %w[install require]
      else [phase]
      end
      phases.each { |entry| @baseline.capture(phase: entry, **baseline_options) }
    end

    def observation_mode
      {"offline" => @offline, "honeypot" => true, "env_profile" => @env_profile,
       "writes_only" => @session_options[:writes_only], "real_home" => @environment_options[:real_home],
       "cwd" => @environment_options[:cwd] && File.expand_path(@environment_options[:cwd]),
       "enforce" => @enforce && Digest::SHA256.file(@enforce).hexdigest, "repeat" => @repeat}
    end

    private

    def validate_invocation!(phase, executable, arguments)
      raise ArgumentError, "arguments must be strings without NUL bytes" unless arguments.is_a?(Array) && arguments.all? { |argument| argument.is_a?(String) && !argument.include?("\0") }
      raise ArgumentError, "executable and arguments only apply to exec phase" if phase != "exec" && (executable || !arguments.empty?)
      raise ArgumentError, "invalid executable name" if executable && !(executable.is_a?(String) && executable.match?(ResultStore::COMPONENT))
    end

    def annotate_stability(paths)
      paths.map { |path| ResultStore.load(path) }.group_by { |manifest| manifest.fetch("phase") }.each_value do |samples|
        keys = samples.map { |manifest| CapabilityKeys.call(manifest) }
        complete = samples.size == @repeat && samples.all? { |manifest| manifest.fetch("errors").empty? }
        stable = complete ? keys.reduce { |intersection, entries| intersection & entries } : []
        flaky = keys.flatten.uniq - stable
        samples.each do |manifest|
          manifest["stability"] = {"samples" => samples.size, "complete" => complete, "stable" => stable.sort, "flaky" => flaky.sort}
          @store.write(manifest)
        end
      end
    end

    def validate!(name, phase, version = nil, require_path: nil)
      raise ArgumentError, "invalid gem name" unless name.is_a?(String) && name.match?(Gem::Specification::VALID_NAME_PATTERN) && name.match?(/[a-zA-Z]/) && !name.start_with?(".", "-", "_")
      raise ArgumentError, "phase must be require, install, plugin, exec or all" unless PHASES.include?(phase)
      raise ArgumentError, "invalid gem version" if version && !Gem::Version.correct?(version)
      raise ArgumentError, "require path must not be empty" if require_path == ""
      raise ArgumentError, "require path only applies to require or all phase" if require_path && !%w[require all].include?(phase)
    end

    def baseline_options
      {offline: @offline, writes_only: @session_options[:writes_only], env_profile: @env_profile, enforce: @enforce}
    end

    def session_options(phase, specification, environment = nil)
      options = @session_options.merge(timeout: @timeout || ((phase == "install") ? 600 : 60))
      options[:redactor] = environment.honeypot if environment
      options[:trace] = "#{@trace}.#{specification.name}.#{specification.version}.#{@run.fetch("id")}.#{phase}.jsonl" if @trace
      options
    end

    def observe_require(environment, specification, specifications, require_path, package: nil)
      baseline = @baseline.capture(phase: "require", **baseline_options)
      begin
        collector, require_path = Phase::Require.call(environment, specification, require_path:, **session_options("require", specification, environment))
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
        {"install" => "build_failed", "exec" => "exec_failed", "plugin" => "plugin_failed"}.fetch(phase, "require_failed")
      end
      environment.honeypot ? environment.honeypot.redact(data) : data
    end

    def save(manifest)
      manifest["findings"] = Policy.new.findings(manifest)
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
