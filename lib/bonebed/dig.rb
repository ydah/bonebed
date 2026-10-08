# frozen_string_literal: true

require "fileutils"
require "json"
require "rbconfig"
require "rubygems/package"
require "rubygems/resolver"
require "rubygems/stub_specification"
require "tmpdir"
require "bundler"
require_relative "baseline"
require_relative "difference"
require_relative "path_normalizer"
require_relative "session"

module Bonebed
  class Dig
    PHASES = %w[require install].freeze
    ROUTINE_RUBYGEMS_PREFIXES = %w[$HOME/.cache/gem/ $HOME/.local/share/gem/].freeze
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
      manifest = Bundler.with_unbundled_env do
        Bundler.reset!
        Gem::Specification.reset
        baseline = @baseline.capture
        phase == "install" ? install(name, version, baseline) : require_gem(name, version, require_path, baseline)
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

    def result_exists?(name, phase:, version: nil, require_path: nil)
      validate!(name, phase, version, require_path:)
      suffix = version ? safe_component(version) : "*"
      Dir[File.join(@results_dir, "#{name}-#{suffix}-#{phase}.json")].any? do |path|
        manifest = JSON.parse(File.read(path))
        manifest.dig("gem", "name") == name &&
          manifest.fetch("errors", []).empty? &&
          (!require_path || manifest.dig("gem", "require_path") == require_path)
      rescue JSON::ParserError
        false
      end
    end

    private

    def validate!(name, phase, version = nil, require_path: nil)
      raise ArgumentError, "invalid gem name" unless valid_gem_name?(name)
      raise ArgumentError, "phase must be require or install" unless PHASES.include?(phase)
      raise ArgumentError, "invalid gem version" if version && !Gem::Version.correct?(version)
      raise ArgumentError, "require path must not be empty" if require_path == ""
      raise ArgumentError, "require path only applies to require phase" if require_path && phase != "require"
    end

    def valid_gem_name?(name)
      name.is_a?(String) &&
        name.match?(Gem::Specification::VALID_NAME_PATTERN) &&
        name.match?(/[a-zA-Z]/) &&
        !name.start_with?(".", "-", "_")
    end

    def require_gem(name, version, require_path, baseline)
      specification = Gem::Specification.find_by_name(name, version ? "=#{version}" : Gem::Requirement.default)
      require_path ||= inferred_require_path(specification)
      unless require_path
        executables = specification.executables.join(", ")
        detail = executables.empty? ? "" : "; executables: #{executables}"
        error = Gem::LoadError.new("#{specification.full_name} has no requirable entrypoint#{detail}; use --require PATH if needed")
        return manifest(name, specification.version.to_s, "require", empty_observation(error), baseline,
          platform: specification.platform.to_s)
      end

      Dir.mktmpdir("bonebed-require-") do |root|
        gem_home = File.join(root, "gems")
        isolate_runtime_gems(specification, gem_home)
        env = {"GEM_HOME" => gem_home, "GEM_PATH" => gem_home}
        code = 'gem ARGV[0], "=#{ARGV[1]}"; require ARGV[2]'
        collector = Session.new([RbConfig.ruby, "-e", code, name, specification.version.to_s, require_path],
          env:, timeout: @timeout, offline: @offline).run
        normalizer = PathNormalizer.new(gem_paths: [gem_home, *Gem.path], tmpdir: root)
        manifest(name, specification.version.to_s, "require", collector.snapshot(normalizer), baseline,
          platform: specification.platform.to_s, require_path:)
      end
    end

    def inferred_require_path(specification)
      paths = [specification.name, specification.name.tr("-", "/")]
      paths.find do |path|
        specification.contains_requirable_file?(path)
      end || matching_top_level_file(specification)
    end

    def matching_top_level_file(specification)
      normalized_name = specification.name.delete("-_")
      paths = specification.full_require_paths.flat_map do |root|
        Dir[File.join(root, "*.{rb,#{RbConfig::CONFIG.fetch("DLEXT")}}")].map { |file| File.basename(file, ".*") }
      end.uniq
      paths.find { |path| path.delete("-_") == normalized_name } || (paths.first if paths.one?)
    end

    def isolate_runtime_gems(specification, gem_home)
      dependency = Gem::Dependency.new(specification.name, "=#{specification.version}")
      specifications = Gem::Resolver.for_current_gems([dependency]).resolve.map(&:spec).uniq(&:full_name)
      FileUtils.mkdir_p([File.join(gem_home, "gems"), File.join(gem_home, "specifications")])
      specifications.each do |resolved|
        FileUtils.ln_s(resolved.full_gem_path, File.join(gem_home, "gems", resolved.full_name))
        FileUtils.ln_s(resolved.loaded_from, File.join(gem_home, "specifications", File.basename(resolved.loaded_from)))
        link_extension(resolved, gem_home)
      end
    end

    def link_extension(specification, gem_home)
      extension_dir = specification.extension_dir
      prefix = "#{specification.base_dir}/"
      return unless Dir.exist?(extension_dir) && extension_dir.start_with?(prefix)

      destination = File.join(gem_home, extension_dir.delete_prefix(prefix))
      FileUtils.mkdir_p(File.dirname(destination))
      FileUtils.ln_s(extension_dir, destination)
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
        gems = installed_gems(gem_home)
        installed = gems.find { |gem| gem.fetch("name") == name }
        cached = cached_gem(gem_home, name)
        normalizer = PathNormalizer.new(home:, gem_paths: [gem_home, *Gem.path], tmpdir: root)
        manifest(name, installed&.fetch("version") || cached&.version&.to_s || version || "unknown", "install",
          collector.snapshot(normalizer), baseline,
          platform: installed&.fetch("platform") || cached&.platform&.to_s, installed_gems: gems)
      end
    end

    def cached_gem(gem_home, name)
      Dir[File.join(gem_home, "cache", "*.gem")].filter_map do |path|
        specification = Gem::Package.new(path).spec
        specification if specification.name == name
      rescue Gem::Package::Error
        nil
      end.max_by(&:version)
    end

    def installed_gems(gem_home)
      specifications = File.join(gem_home, "specifications")
      Dir[File.join(specifications, "*.gemspec")].filter_map do |path|
        specification = Gem::StubSpecification.gemspec_stub(path, gem_home, File.join(gem_home, "gems"))
        next unless specification.valid?

        {"name" => specification.name, "version" => specification.version.to_s, "platform" => specification.platform.to_s}
      end.sort_by { |gem| gem.values_at("name", "version", "platform") }
    end

    def manifest(name, version, phase, observation, baseline, platform: nil, require_path: nil, installed_gems: nil)
      observation = Difference.call(observation, baseline.observation)
      files = observation.fetch(:files).transform_values { |entries| entries.keys.sort }
      files[:notable] = (files[:read].grep(/\A(?:\$HOME|\$PWD)\//) + files[:write].grep(/\A(?:\$HOME|\$PWD|\$TMPDIR)\//)).uniq.sort
        .reject { |path| ROUTINE_RUBYGEMS_PREFIXES.any? { |prefix| path.start_with?(prefix) } }
      gem = {"name" => name, "version" => version}
      gem["platform"] = platform if platform
      gem["require_path"] = require_path if require_path
      data = {
        "schema_version" => 1,
        "gem" => gem,
        "phase" => phase,
        "environment" => {"ruby" => RUBY_VERSION, "arch" => RbConfig::CONFIG.fetch("host_cpu"), "kernel" => `uname -r`.strip, "baseline_id" => baseline.id},
        "files" => stringify_keys(files),
        "network" => counted_entries(observation.fetch(:network)),
        "exec" => counted_entries(observation.fetch(:exec)),
        "threads" => counted_entries(observation.fetch(:threads)),
        "stats" => stringify_keys(observation.fetch(:stats)),
        "errors" => observation.fetch(:errors),
        "stdout" => observation.fetch(:stdout, ""),
        "stderr" => observation.fetch(:stderr, "")
      }
      data["installed_gems"] = installed_gems if installed_gems
      data
    end

    def counted_entries(entries)
      entries.map { |event, count| stringify_keys(event).merge("count" => count) }.sort_by(&:to_s)
    end

    def stringify_keys(hash)
      hash.to_h { |key, value| [key.to_s, value] }
    end

    def empty_observation(error = nil)
      {
        files: {read: {}, write: {}}, network: {}, exec: {}, threads: {},
        stats: {openat_total: 0, notify_roundtrips: 0, wall_ms: 0},
        errors: error ? ["#{error.class}: #{error.message}"] : [], stdout: "", stderr: ""
      }
    end

    def safe_component(value)
      value.to_s.gsub(/[^0-9A-Za-z._-]/, "_")
    end
  end
end
