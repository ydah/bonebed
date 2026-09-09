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

    def initialize(results_dir: "results", timeout: 30, offline: false, baseline: Baseline.new(timeout:))
      @results_dir = results_dir
      @timeout = timeout
      @offline = offline
      @baseline = baseline
    end

    def run(name, phase: "require", version: nil)
      validate!(name, phase)
      manifest = if phase == "install"
        Bundler.with_unbundled_env { install(name, version, @baseline.capture) }
      else
        require_gem(name, version, @baseline.capture)
      end
      FileUtils.mkdir_p(@results_dir)
      path = File.join(@results_dir, "#{name}-#{manifest.dig("gem", "version")}-#{phase}.json")
      File.write(path, "#{JSON.pretty_generate(manifest)}\n")
      path
    end

    private

    def validate!(name, phase)
      raise ArgumentError, "gem name is required" unless name&.match?(/\A[a-zA-Z0-9_-]+\z/)
      raise ArgumentError, "phase must be require or install" unless PHASES.include?(phase)
    end

    def require_gem(name, version, baseline)
      specification = Gem::Specification.find_by_name(name, version ? "=#{version}" : Gem::Requirement.default)
      code = 'gem ARGV[0], "=#{ARGV[1]}"; require ARGV[0]'
      collector = Session.new([RbConfig.ruby, "-e", code, name, specification.version.to_s], timeout: @timeout, offline: @offline).run
      normalizer = PathNormalizer.new
      manifest(name, specification.version.to_s, "require", collector.snapshot(normalizer), baseline)
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

    def manifest(name, version, phase, observation, baseline)
      observation = Difference.call(observation, baseline.observation)
      files = observation.fetch(:files).transform_values { |entries| entries.keys.sort }
      files[:notable] = (files[:read].grep(/\A\$HOME\//) + files[:write].grep(/\A(?:\$HOME|\$TMPDIR)\//)).uniq.sort
      {
        "schema_version" => 1,
        "gem" => {"name" => name, "version" => version},
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
  end
end
