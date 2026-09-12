# frozen_string_literal: true

require "fileutils"
require "json"
require "rbconfig"
require "tmpdir"
require "bundler"
require_relative "baseline"
require_relative "difference"
require_relative "path_normalizer"
require_relative "session"

module Bonebed
  class Dig
    PHASES = %w[require install].freeze
    attr_reader :results_dir, :last_errors

    def initialize(results_dir: "results", timeout: 30, offline: false, baseline: Baseline.new(timeout:))
      raise ArgumentError, "timeout must be positive" unless timeout.positive?

      @results_dir = results_dir
      @timeout = timeout
      @offline = offline
      @baseline = baseline
      @last_errors = []
    end

    def run(name, phase: "require", version: nil, require_path: nil)
      validate!(name, phase, version, require_path:)
      manifest = if phase == "install"
        Bundler.with_unbundled_env { install(name, version, @baseline.capture) }
      else
        require_gem(name, version, require_path || name, @baseline.capture)
      end
      @last_errors = manifest.fetch("errors")
      FileUtils.mkdir_p(@results_dir)
      path = File.join(@results_dir, "#{name}-#{safe_component(manifest.dig("gem", "version"))}-#{phase}.json")
      File.write(path, "#{JSON.pretty_generate(manifest)}\n")
      path
    end

    def write_failure(name, phase:, version:, error:)
      validate!(name, phase)
      FileUtils.mkdir_p(@results_dir)
      path = File.join(@results_dir, "#{name}-#{safe_component(version)}-#{phase}.json")
      data = manifest(name, version, phase, empty_observation(error), Baseline::Result.new(id: nil, observation: empty_observation))
      File.write(path, "#{JSON.pretty_generate(data)}\n")
      path
    end

    def result_exists?(name, phase:, version: nil)
      validate!(name, phase, version)
      suffix = version ? safe_component(version) : "*"
      !Dir[File.join(@results_dir, "#{name}-#{suffix}-#{phase}.json")].empty?
    end

    private

    def validate!(name, phase, version = nil, require_path: nil)
      raise ArgumentError, "gem name is required" unless name&.match?(/\A[a-zA-Z0-9_-]+\z/)
      raise ArgumentError, "phase must be require or install" unless PHASES.include?(phase)
      raise ArgumentError, "invalid gem version" if version && !Gem::Version.correct?(version)
      raise ArgumentError, "require path must not be empty" if require_path == ""
      raise ArgumentError, "require path only applies to require phase" if require_path && phase != "require"
    end

    def require_gem(name, version, require_path, baseline)
      specification = Gem::Specification.find_by_name(name, version ? "=#{version}" : Gem::Requirement.default)
      code = 'gem ARGV[0], "=#{ARGV[1]}"; require ARGV[2]'
      collector = Session.new([RbConfig.ruby, "-e", code, name, specification.version.to_s, require_path], timeout: @timeout, offline: @offline).run
      normalizer = PathNormalizer.new
      manifest(name, specification.version.to_s, "require", collector.snapshot(normalizer), baseline, require_path:)
    end

    def install(name, version, baseline)
      Dir.mktmpdir("bonebed-install-") do |root|
        gem_home = File.join(root, "gems")
        home = File.join(root, "home")
        FileUtils.mkdir_p(home)
        requested = version ? "#{name}:#{version}" : name
        command = [RbConfig.ruby, "-S", "gem", "install", requested, "--no-document", "--install-dir", gem_home]
        env = {"GEM_HOME" => gem_home, "GEM_PATH" => gem_home, "HOME" => home}
        collector = Session.new(command, env:, timeout: @timeout, offline: @offline).run
        installed_version = installed_version(gem_home, name) || version || "unknown"
        normalizer = PathNormalizer.new(home:, gem_paths: [gem_home, *Gem.path], tmpdir: root)
        manifest(name, installed_version, "install", collector.snapshot(normalizer), baseline)
      end
    end

    def installed_version(gem_home, name)
      path = Dir[File.join(gem_home, "specifications", "#{name}-*.gemspec")].max
      File.basename(path, ".gemspec").delete_prefix("#{name}-") if path
    end

    def manifest(name, version, phase, observation, baseline, require_path: nil)
      observation = Difference.call(observation, baseline.observation)
      files = observation.fetch(:files).transform_values { |entries| entries.keys.sort }
      files[:notable] = (files[:read].grep(/\A\$HOME\//) + files[:write].grep(/\A(?:\$HOME|\$TMPDIR)\//)).uniq.sort
      gem = {"name" => name, "version" => version}
      gem["require_path"] = require_path if require_path
      {
        "schema_version" => 1,
        "gem" => gem,
        "phase" => phase,
        "environment" => {"ruby" => RUBY_VERSION, "arch" => RbConfig::CONFIG.fetch("host_cpu"), "kernel" => `uname -r`.strip, "baseline_id" => baseline.id},
        "files" => stringify_keys(files),
        "network" => counted_entries(observation.fetch(:network)),
        "exec" => counted_entries(observation.fetch(:exec)),
        "stats" => stringify_keys(observation.fetch(:stats)),
        "errors" => observation.fetch(:errors)
      }
    end

    def counted_entries(entries)
      entries.map { |event, count| stringify_keys(event).merge("count" => count) }.sort_by(&:to_s)
    end

    def stringify_keys(hash)
      hash.to_h { |key, value| [key.to_s, value] }
    end

    def empty_observation(error = nil)
      {
        files: {read: {}, write: {}}, network: {}, exec: {},
        stats: {openat_total: 0, notify_roundtrips: 0, wall_ms: 0},
        errors: error ? ["#{error.class}: #{error.message}"] : []
      }
    end

    def safe_component(value)
      value.to_s.gsub(/[^0-9A-Za-z._-]/, "_")
    end
  end
end
