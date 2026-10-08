# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "tempfile"
require_relative "sensitive_path"

module Bonebed
  class ResultStore
    COMPONENT = /\A[0-9A-Za-z][0-9A-Za-z._-]*\z/
    MODE_KEYS = %w[offline honeypot env_profile writes_only real_home cwd enforce repeat].freeze

    def initialize(directory)
      @directory = directory
    end

    def write(manifest)
      manifest = JSON.parse(JSON.generate(manifest))
      raise ArgumentError, "invalid schema v2 manifest" unless manifest["schema_version"] == 2 && self.class.valid?(manifest)

      path = path_for(manifest)
      directory = File.dirname(path)
      FileUtils.mkdir_p(directory)
      Tempfile.create([".manifest-", ".tmp"], directory) do |file|
        file.write(JSON.pretty_generate(manifest) << "\n")
        file.flush
        file.fsync
        File.rename(file.path, path)
      end
      path
    end

    def exists?(name, **options)
      !matching(name, **options).empty?
    end

    def matching(name, phase:, version: nil, require_path: nil, platform: nil, mode: nil, executable: nil, arguments: nil)
      matches = self.class.read(@directory).select do |manifest|
        gem = manifest.fetch("gem")
        gem["name"] == name && manifest["phase"] == phase &&
          (!version || gem["version"] == version.to_s) && (!platform || gem["platform"] == platform.to_s) &&
          (!require_path || phase == "install" || gem["require_path"] == require_path) &&
          (!mode || self.class.mode_identity(manifest.dig("run", "mode")) == self.class.mode_identity(mode)) &&
          (!executable || manifest.dig("run", "executable") == executable) &&
          (!arguments || manifest.dig("run", "arguments") == arguments) &&
          manifest.fetch("errors").empty? &&
          !manifest.dig("target", "timed_out") && !manifest.dig("target", "signal") &&
          [nil, 0].include?(manifest.dig("target", "exit_status"))
      end
      count = mode && mode.transform_keys(&:to_s)["repeat"]
      return matches unless count && count > 1

      matches.select { |manifest| manifest.dig("run", "repeat") }.group_by { |manifest| [manifest.fetch("gem").values_at("version", "platform", "require_path"), manifest.dig("run", "repeat", "group")] }
        .values.select do |samples|
          samples.map { |sample| sample.dig("run", "repeat", "index") }.sort == (1..count).to_a &&
            samples.all? { |sample| sample.dig("run", "repeat", "count") == count && sample["stability"].is_a?(Hash) && sample["stability"]["complete"] == true }
        end.flatten(1)
    end

    def migrate
      self.class.paths(@directory).filter_map do |path|
        manifest = self.class.load(path)
        next unless manifest && manifest.fetch("schema_version", 1) == 1

        migrated = self.class.upgrade(manifest)
        destination = path_for(migrated)
        self.class.load(destination) ? destination : write(migrated)
      end
    end

    def self.read(directory)
      paths(directory).filter_map do |path|
        manifest = load(path)
        [manifest, File.mtime(path)] if manifest
      rescue SystemCallError
        nil
      end.group_by { |manifest, _mtime| identity(manifest) }
        .values.map { |versions| versions.max_by { |manifest, mtime| [manifest.fetch("schema_version", 1), mtime] }.first }
    end

    def self.mode_identity(mode)
      {"repeat" => 1}.merge((mode || {}).transform_keys(&:to_s)).values_at(*MODE_KEYS)
    end

    def self.identity(manifest)
      [manifest["phase"], *manifest.fetch("gem").values_at("name", "version", "platform", "require_path"),
        mode_identity(manifest.dig("run", "mode")), manifest["command"], manifest.dig("run", "repeat")&.values_at("group", "index"),
        manifest.dig("run", "executable"), manifest.dig("run", "arguments"), manifest["bundle"]]
    end

    def self.paths(directory)
      Dir[File.join(directory, "**", "*.json")].sort
    end

    def self.load(path)
      manifest = JSON.parse(File.read(path))
      manifest if valid?(manifest)
    rescue JSON::ParserError, SystemCallError
      nil
    end

    def self.valid?(manifest)
      return false unless manifest.is_a?(Hash) && [1, 2].include?(manifest.fetch("schema_version", 1))

      gem = manifest["gem"]
      return false unless gem.is_a?(Hash)
      return false unless %w[name version].all? { |key| gem[key].is_a?(String) && COMPONENT.match?(gem[key]) }
      return false if !gem["platform"].nil? && !(gem["platform"].is_a?(String) && COMPONENT.match?(gem["platform"]))
      return false unless gem["require_path"].nil? || gem["require_path"].is_a?(String)
      return false unless %w[install require plugin exec].include?(manifest["phase"])
      return false unless manifest["errors"].is_a?(Array) && manifest["errors"].all? { |error| error.is_a?(String) }
      return false unless valid_run?(manifest["run"])
      return false if manifest.key?("command") && !(manifest["command"].is_a?(Array) && !manifest["command"].empty? && manifest["command"].all? { |arg| arg.is_a?(String) })

      files = manifest["files"]
      return false unless files.is_a?(Hash) && files["write"].is_a?(Array)

      read = files["read"]
      if manifest["schema_version"] == 2
        return false unless read.is_a?(Hash) && %w[self resolver other].all? { |key| read[key].is_a?(Array) }
        read = read.values.flatten
      end
      read.is_a?(Array) && (read + files["write"]).all? { |path| path.is_a?(String) } &&
        %w[network exec threads].all? { |key| !manifest.key?(key) || (manifest[key].is_a?(Array) && manifest[key].all? { |entry| valid_event?(key, entry) }) } &&
        (!manifest.key?("stats") || manifest["stats"].is_a?(Hash)) &&
        (manifest["target"].nil? || manifest["target"].is_a?(Hash)) &&
        %w[stdout stderr].all? { |key| !manifest.key?(key) || manifest[key].is_a?(String) } &&
        (manifest["observer_errors"].nil? || (manifest["observer_errors"].is_a?(Array) && manifest["observer_errors"].all? { |error| error.is_a?(String) }))
    end

    def self.valid_run?(run)
      return true if run.nil?
      return false unless run.is_a?(Hash)
      return false if !run["executable"].nil? && !(run["executable"].is_a?(String) && COMPONENT.match?(run["executable"]))
      return false if !run["arguments"].nil? && !(run["arguments"].is_a?(Array) && run["arguments"].all? { |argument| argument.is_a?(String) && !argument.include?("\0") })
      unless run["repeat"].nil?
        repetition = run["repeat"]
        return false unless repetition.is_a?(Hash) && repetition["group"].is_a?(String) &&
          repetition["count"].is_a?(Integer) && (2..100).cover?(repetition["count"]) &&
          repetition["index"].is_a?(Integer) && (1..repetition["count"]).cover?(repetition["index"])
      end

      mode = run["mode"]
      return true if mode.nil?
      return false unless mode.is_a?(Hash)

      %w[offline honeypot writes_only real_home].all? { |key| [nil, true, false].include?(mode[key]) } &&
        %w[env_profile cwd enforce].all? { |key| mode[key].nil? || mode[key].is_a?(String) } &&
        (!mode.key?("repeat") || (mode["repeat"].is_a?(Integer) && (1..100).cover?(mode["repeat"])))
    end
    private_class_method :valid_run?

    def self.valid_event?(kind, entry)
      return false unless entry.is_a?(Hash)
      return false if entry.key?("count") && !(entry["count"].is_a?(Integer) && entry["count"].positive?)

      case kind
      when "network"
        return false unless entry["family"].is_a?(String)
        return entry["path"].is_a?(String) if entry["family"] == "unix"
        return true unless %w[inet inet6].include?(entry["family"])

        entry["addr"].is_a?(String) && entry["port"].is_a?(Integer) && (0..65_535).cover?(entry["port"])
      when "exec"
        entry["path"].is_a?(String) && (!entry.key?("argv") || (entry["argv"].is_a?(Array) && entry["argv"].all? { |value| value.is_a?(String) }))
      when "threads"
        entry["syscall"].is_a?(String)
      end
    end
    private_class_method :valid_event?

    def self.capabilities(manifest)
      read = manifest.dig("files", "read")
      read = read.values.flatten if read.is_a?(Hash)
      read = Array(read)
      write = Array(manifest.dig("files", "write"))
      gem = manifest.fetch("gem", {})
      sensitive = SensitivePath::ABSOLUTE + SensitivePath::HOME.map { |path| "$HOME/#{path}" } + SensitivePath::PROJECT.map { |path| "$PWD/#{path}" }
      {
        "network" => !Array(manifest["network"]).empty?, "dns" => manifest["dns"] && !manifest["dns"].empty?,
        "exec" => !Array(manifest["exec"]).empty?, "process" => manifest["processes"] && !manifest["processes"].empty?,
        "threads" => !Array(manifest["threads"]).empty?,
        "home_read" => read.any? { |path| path.start_with?("$HOME/") },
        "home_write" => write.any? { |path| path.start_with?("$HOME/") },
        "project_write" => write.any? { |path| path.start_with?("$PWD/") },
        "sensitive_read" => read.any? { |path| sensitive.any? { |pattern| File.fnmatch?(pattern, path, SensitivePath::FLAGS) } },
        "native_extension" => gem["extensions"] && !gem["extensions"].empty?,
        "plugin" => gem["rubygems_plugin"],
        "suspicious_syscalls" => manifest["suspicious"] && !manifest["suspicious"].empty?,
        "anti_analysis" => manifest["anti_analysis"] && !manifest["anti_analysis"].empty?
      }
    end

    def self.upgrade(manifest)
      data = JSON.parse(JSON.generate(manifest))
      data["schema_version"] = 2
      data["tool"] ||= {"name" => "bonebed", "version" => nil, "seccomp_notify" => nil}
      data["run"] = {"id" => "migrated-#{Digest::SHA256.hexdigest(JSON.generate(manifest))}",
                     "started_at" => data.delete("started_at"), "mode" => {"offline" => nil, "honeypot" => nil}}
      data["target"] ||= {"exit_status" => nil, "signal" => nil, "timed_out" => nil}
      %w[platform require_path sha256 extensions executables rubygems_plugin].each { |key| data["gem"][key] = nil unless data["gem"].key?(key) }
      %w[observer_errors dependencies canary_hits stdout_truncated stderr_truncated].each { |key| data[key] = nil unless data.key?(key) }
      data["files"]["read"] = {"self" => [], "resolver" => [], "other" => data["files"].fetch("read")}
      data["stats"] ||= {}
      {"openat_total" => "open_total", "openat_after_baseline" => "open_after_baseline"}.each do |old, current|
        data["stats"][current] = data["stats"].delete(old)
      end
      data["capabilities"] = capabilities(data)
      data
    end

    private

    def path_for(manifest)
      gem = manifest.fetch("gem")
      suffix = Digest::SHA256.hexdigest(JSON.generate(self.class.identity(manifest)))
      filename = "#{gem.fetch("version")}-#{gem["platform"] || "unknown"}+#{suffix}.json"
      File.join(@directory, manifest.fetch("phase"), gem.fetch("name"), filename)
    end
  end
end
