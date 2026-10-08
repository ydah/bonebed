# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "rbconfig"
require "rubygems/package"
require "tempfile"
require_relative "path_normalizer"
require_relative "session"
require_relative "gem_environment"
require_relative "phase/install"
require_relative "phase/require"
require_relative "phase/plugin"
require_relative "enforcement"

module Bonebed
  class Baseline
    CACHE_VERSION = 7
    Result = Struct.new(:id, :observation)

    def initialize(cache_dir: ENV.fetch("BONEBED_BASELINE_DIR", ".bonebed/baselines"), timeout: 30)
      @cache_dir = File.expand_path(cache_dir)
      @timeout = timeout
    end

    def capture(refresh: false, phase: "require", offline: false, writes_only: false, env_profile: "dev", enforce: nil)
      mode = {offline:, writes_only:, env_profile:, enforce:}
      raise ArgumentError, "invalid baseline phase" unless %w[install require plugin].include?(phase)
      cache_path = File.join(@cache_dir, "#{id(phase, **mode)}.json")
      unless refresh || !File.file?(cache_path)
        begin
          return Result.new(id: id(phase, **mode), observation: decode(JSON.parse(File.read(cache_path))))
        rescue JSON::ParserError, KeyError, TypeError
          # A partial or obsolete cache is safe to regenerate.
        end
      end
      observation = observe(phase, **mode)
      errors = observation.fetch(:errors) + observation.fetch(:observer_errors)
      raise Error, errors.join("; ") unless errors.empty?

      FileUtils.mkdir_p(@cache_dir)
      Tempfile.create(["baseline", ".json"], @cache_dir) do |file|
        file.write(JSON.generate(encode(observation)))
        file.close
        File.rename(file.path, cache_path)
      end
      Result.new(id: id(phase, **mode), observation:)
    end

    private

    def id(phase = "require", offline: false, writes_only: false, env_profile: "dev", enforce: nil)
      runtime = [phase, RbConfig.ruby, RUBY_REVISION, RUBY_VERSION, Gem::VERSION, RbConfig::CONFIG["host_cpu"],
        ENV["RUBYOPT"], CACHE_VERSION, "honeypot-copy-v1", offline, writes_only, env_profile,
        enforce && Digest::SHA256.file(enforce).hexdigest]
      "v#{CACHE_VERSION}-#{phase}-#{Digest::SHA256.hexdigest(runtime.join("\0"))[0, 24]}"
    end

    def observe(phase, offline:, writes_only:, env_profile:, enforce:)
      GemEnvironment.open do |environment|
        session_options = {timeout: @timeout, quiet_target: true, offline:, writes_only:}
        session_options[:enforcement] = Enforcement.load(enforce, environment) if enforce
        environment.env.merge!({"CI" => "true", "GITHUB_ACTIONS" => "true", "GITHUB_REPOSITORY" => "example/app"}) if env_profile == "ci"
        environment.env.merge!({"RAILS_ENV" => "production", "RACK_ENV" => "production"}) if env_profile == "prod"
        specification = empty_specification
        package = build_empty(environment, specification)
        if phase == "plugin"
          Phase::Install.call(environment, [package], **session_options)
          collector = Phase::Plugin.call(environment, **session_options)
        elsif phase == "install"
          collector = Phase::Install.call(environment, [package], **session_options)
        else
          directory = File.join(environment.gem_home, "gems", specification.full_name)
          FileUtils.mkdir_p(File.join(directory, "lib"))
          File.write(File.join(directory, "lib", "bonebed_baseline_empty.rb"), "")
          FileUtils.mkdir_p(File.join(environment.gem_home, "specifications"))
          File.write(File.join(environment.gem_home, "specifications", "#{specification.full_name}.gemspec"), specification.to_ruby)
          collector, = Phase::Require.call(environment, specification, require_path: "bonebed_baseline_empty", **session_options)
        end
        normalizer = PathNormalizer.new(home: environment.home, cwd: environment.project,
          gem_paths: [environment.gem_home, *Gem.path], tmpdir: environment.root)
        collector.snapshot(normalizer)
      end
    end

    def empty_specification
      Gem::Specification.new do |spec|
        spec.name = "bonebed-baseline-empty"
        spec.version = "1.0.0"
        spec.summary = "Empty observation baseline"
        spec.authors = ["Bonebed"]
        spec.homepage = "https://github.com/ydah/bonebed"
        spec.license = "MIT"
        spec.required_ruby_version = ">= 3.2"
        spec.files = ["lib/bonebed_baseline_empty.rb"]
      end
    end

    def build_empty(environment, specification)
      FileUtils.mkdir_p(File.join(environment.prefetch, "lib"))
      File.write(File.join(environment.prefetch, "lib", "bonebed_baseline_empty.rb"), "")
      Dir.chdir(environment.prefetch) do
        Gem::DefaultUserInteraction.use_ui(Gem::SilentUI.new) { Gem::Package.build(specification) }
      end
      File.join(environment.prefetch, "#{specification.full_name}.gem")
    end

    def encode(observation)
      observation.merge(**(%i[network exec threads] + Collector::EVENT_GROUPS).to_h { |key| [key, observation.fetch(key).map { |event, count| {event:, count:} }] })
    end

    def decode(observation)
      observation.transform_keys(&:to_sym).merge(
        files: observation.fetch("files").to_h { |mode, values| [mode.to_sym, values] },
        **(%i[network exec threads] + Collector::EVENT_GROUPS).to_h { |key| [key, decode_entries(observation.fetch(key.to_s, []))] },
        stats: observation.fetch("stats").transform_keys(&:to_sym)
      )
    end

    def decode_entries(entries)
      entries.to_h do |entry|
        event = entry.fetch("event").transform_keys(&:to_sym)
        event[:operation] = event[:operation].to_sym if event[:operation]
        [event, entry.fetch("count")]
      end
    end
  end
end
