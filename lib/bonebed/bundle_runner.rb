# frozen_string_literal: true

require "bundler"
require "digest"
require "securerandom"
require "time"
require "uri"
require_relative "baseline"
require_relative "bundler_runtime"
require_relative "enforcement"
require_relative "gem_environment"
require_relative "manifest_builder"
require_relative "policy"
require_relative "prefetcher"
require_relative "result_store"

module Bonebed
  class BundleRunner
    attr_reader :last_errors, :last_observer_errors

    def initialize(results_dir: "results", timeout: 600, offline: false, sinkhole: false, env_profile: "dev", writes_only: false,
      trace: nil, enforce: nil, deny: nil, quiet_target: false, output_limit: Session::OUTPUT_LIMIT, argv_limit: 64,
      cwd: nil, real_home: false, prefetcher: Prefetcher.new)
      raise ArgumentError, "sinkhole must be a boolean" unless [true, false].include?(sinkhole)
      raise ArgumentError, "offline and sinkhole cannot be combined" if offline && sinkhole
      raise ArgumentError, "trace is unsupported with sinkhole" if sinkhole && trace
      raise ArgumentError, "deny is incompatible with writes-only capture" if deny && writes_only
      raise ArgumentError, "timeout must be positive" unless timeout.is_a?(Numeric) && timeout.positive?
      raise ArgumentError, "invalid environment profile" unless %w[dev ci prod].include?(env_profile)
      raise ArgumentError, "output limit must be nonnegative" unless output_limit.is_a?(Integer) && output_limit >= 0
      raise ArgumentError, "argv limit must be positive" unless argv_limit.is_a?(Integer) && argv_limit.positive?

      @store = ResultStore.new(results_dir)
      @prefetcher = prefetcher
      @cwd = cwd && File.expand_path(cwd)
      @real_home = real_home
      @env_profile = env_profile
      @enforce = enforce
      @deny = DenyPolicy.load(deny) if deny
      @trace = trace
      @session_options = {timeout:, offline:, sinkhole:, writes_only:, quiet_target:, output_limit:, argv_limit:, target_stdout: $stderr}
      @last_errors = []
      @last_observer_errors = []
    end

    def run(gemfile: "Gemfile", lockfile: nil)
      @fatal_observer_error = false
      @last_errors = []
      @last_observer_errors = []
      @bundle = {}
      @run = nil
      @run = {"id" => SecureRandom.uuid, "kind" => "bundle", "started_at" => Time.now.utc.iso8601,
              "mode" => @session_options.slice(:offline, :sinkhole, :writes_only).transform_keys(&:to_s).merge(
                "env_profile" => @env_profile, "honeypot" => true, "real_home" => @real_home, "cwd" => @cwd,
                "enforce" => @enforce && Digest::SHA256.file(@enforce).hexdigest,
                "deny" => @deny && DenyPolicy.digest(@deny)
              )}
      gemfile = File.expand_path(gemfile, @cwd || Dir.pwd)
      lockfile = lockfile ? File.expand_path(lockfile, @cwd || Dir.pwd) : "#{gemfile}.lock"
      gemfile_contents = File.binread(gemfile)
      lockfile_contents = File.binread(lockfile)
      @bundle = {"gemfile_sha256" => Digest::SHA256.hexdigest(gemfile_contents), "lockfile_sha256" => Digest::SHA256.hexdigest(lockfile_contents)}
      locked = locked_specifications(lockfile_contents)
      packages = prefetch(locked)
      baseline = capture_baseline
      GemEnvironment.open(real_home: @real_home) do |environment|
        configure(environment)
        File.binwrite(File.join(environment.project, "Gemfile"), gemfile_contents)
        File.binwrite(File.join(environment.project, "Gemfile.lock"), lockfile_contents)
        specifications = packages.map do |package|
          specification = Gem::Package.new(package).spec
          FileUtils.copy_file(package, File.join(environment.project, "vendor", "cache", "#{specification.full_name}.gem"))
          specification
        end
        options = session_options(environment)
        options[:trace] = "#{@trace}.bundle.#{@run.fetch("id")}.install.jsonl" if @trace
        observation = Session.new(command, env: environment.env, cwd: environment.project, unsetenv_others: true, **options).run.snapshot(environment.normalizer)
        manifest = ManifestBuilder.call("bundle", "0", "install", observation, baseline, specifications:, run: @run)
        manifest["command"] = command
        manifest["bundle"] = @bundle
        manifest["failure_reason"] = "bundle_install_failed" unless manifest.fetch("errors").empty?
        save(environment.honeypot.redact(manifest))
      end
    rescue => error
      @fatal_observer_error = error.is_a?(ObserverError)
      observation = empty_observation(error)
      if @fatal_observer_error
        observation[:observer_errors] = observation[:errors]
        observation[:errors] = []
      end
      manifest = ManifestBuilder.call("bundle", "0", "install", observation,
        Baseline::Result.new(id: nil, observation: empty_observation), run: @run)
      manifest["command"] = command
      manifest["bundle"] = @bundle
      manifest["failure_reason"] = if @fatal_observer_error
        "observation_failed"
      else
        error.is_a?(Prefetcher::Error) ? "prefetch_failed" : "setup_failed"
      end
      save(manifest)
    end

    def fatal_observer_error?
      !!@fatal_observer_error
    end

    private

    def locked_specifications(contents)
      parser = Bundler::LockfileParser.new(contents)
      unsupported = parser.sources.reject { |source| source.is_a?(Bundler::Source::Rubygems) }
      raise ArgumentError, "unsupported lockfile sources: git and path sources cannot be bundled" unless unsupported.empty?

      parser.sources.each do |source|
        source.remotes.each do |remote|
          uri = URI(remote.to_s)
          unless uri.scheme == "https" && uri.host == "rubygems.org" && uri.port == 443 && ["", "/"].include?(uri.path) && !uri.userinfo && !uri.query && !uri.fragment
            raise ArgumentError, "unsupported lockfile registry; only https://rubygems.org is supported"
          end
        end
      end
      parser.specs.uniq { |specification| specification.full_name }
    end

    def prefetch(locked)
      expected = locked.map(&:full_name)
      packages = locked.flat_map do |specification|
        @prefetcher.call(specification.name, specification.version.to_s, platform: specification.platform.to_s)
      end.uniq
      selected = packages.select do |path|
        package = Gem::Package.new(path)
        package.verify
        expected.include?(package.spec.full_name)
      end
      missing = expected - selected.map { |path| Gem::Package.new(path).spec.full_name }
      raise Prefetcher::Error, "prefetch did not provide locked gems: #{missing.join(", ")}" unless missing.empty?

      selected
    end

    def configure(environment)
      BundlerRuntime.prepare(environment)
      FileUtils.mkdir_p(File.join(environment.project, "vendor", "cache"))
      bundle_home = File.join(environment.root, "bundle")
      environment.env.merge!(
        "BUNDLE_GEMFILE" => File.join(environment.project, "Gemfile"), "BUNDLE_PATH" => environment.gem_home,
        "BUNDLE_APP_CONFIG" => File.join(environment.project, ".bundle"),
        "BUNDLE_USER_HOME" => bundle_home,
        "BUNDLE_USER_CACHE" => File.join(bundle_home, "cache"),
        "BUNDLE_USER_CONFIG" => File.join(bundle_home, "config"),
        "BUNDLE_CACHE_PATH" => File.join(environment.project, "vendor", "cache"),
        "BUNDLE_IGNORE_CONFIG" => "true", "BUNDLE_DISABLE_SHARED_GEMS" => "true",
        "BUNDLE_DISABLE_VERSION_CHECK" => "true", "BUNDLE_SILENCE_ROOT_WARNING" => "true",
        "BUNDLE_FROZEN" => "true", "BUNDLE_VERSION" => "system", "BUNDLE_JOBS" => "1"
      )
      environment.env.merge!("CI" => "true", "GITHUB_ACTIONS" => "true", "GITHUB_REPOSITORY" => "example/app") if @env_profile == "ci"
      environment.env.merge!("RAILS_ENV" => "production", "RACK_ENV" => "production") if @env_profile == "prod"
    end

    def command
      BundlerRuntime.command("install", "--local")
    end

    def session_options(environment)
      options = @session_options.merge(redactor: environment.honeypot)
      options[:deny] = DenyPolicy.context(@deny, name: "bundle", phase: "install", environment:) if @deny
      options[:enforcement] = Enforcement.load(@enforce, environment) if @enforce
      options
    end

    def capture_baseline
      GemEnvironment.open(real_home: @real_home) do |environment|
        configure(environment)
        File.write(File.join(environment.project, "Gemfile"), "source 'https://rubygems.org'\n")
        File.write(File.join(environment.project, "Gemfile.lock"), "GEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n\nBUNDLED WITH\n   #{Bundler::VERSION}\n")
        observation = Session.new(command, env: environment.env, cwd: environment.project, unsetenv_others: true,
          **session_options(environment).merge(quiet_target: true)).run.snapshot(environment.normalizer)
        errors = observation.fetch(:errors) + observation.fetch(:observer_errors).reject { |error| !@session_options[:sinkhole] && error.start_with?("isolation:") }
        raise ObserverError, "bundle baseline failed: #{errors.join("; ")}" unless errors.empty?

        identity = [command, RUBY_REVISION, Gem::VERSION, Bundler::VERSION, @run.fetch("mode")]
        Baseline::Result.new(id: "bundle-#{Digest::SHA256.hexdigest(JSON.generate(identity))}", observation:)
      end
    rescue Error, SystemCallError => error
      raise ObserverError, "bundle baseline failed: #{error.message}"
    end

    def save(manifest)
      manifest["findings"] = Policy.new.findings(manifest)
      @last_errors = manifest.fetch("errors")
      @last_observer_errors = manifest.fetch("observer_errors")
      @store.write(manifest)
    end

    def empty_observation(error = nil)
      {files: {read: {}, write: {}}, network: {}, exec: {}, threads: {},
       stats: {openat_total: 0, notify_roundtrips: 0, wall_ms: 0},
       errors: error ? ["#{error.class}: #{error.message}"] : [], observer_errors: [], stdout: "", stderr: ""}
    end
  end
end
