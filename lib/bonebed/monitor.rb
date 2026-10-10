# frozen_string_literal: true

require "net/http"
require "timeout"
require "uri"
require_relative "dataset"

module Bonebed
  class Monitor
    RESPONSE_LIMIT = 8 * 1024 * 1024

    def initialize(results_dir:, state_path:, dig:, registry: nil)
      @results_dir = results_dir
      @state_path = File.expand_path(state_path)
      @dig = dig
      @registry = registry || method(:registry_versions)
      @mode = ResultStore.mode_identity(dig.observation_mode)
      @context = Digest::SHA256.hexdigest(JSON.generate([Gem::Platform.local.to_s, @mode]))
    end

    def run(names)
      unless names.is_a?(Array) && names.all? { |name| name.is_a?(String) && ResultStore::COMPONENT.match?(name) }
        raise ArgumentError, "monitor expects an array of valid gem names"
      end
      FileUtils.mkdir_p(File.dirname(@state_path))
      FileUtils.mkdir_p(@results_dir)
      File.open("#{@state_path}.lock", File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
        raise ArgumentError, "monitor state is already in use" unless lock.flock(File::LOCK_EX | File::LOCK_NB)

        state = load_state
        summary = {observed: [], skipped: [], errors: []}
        names.uniq.each { |name| observe_name(name, state, summary) }
        summary[:dataset] = Dataset.new(@results_dir).write(File.join(@results_dir, "dataset"))
        summary
      end
    end

    private

    def observe_name(name, state, summary)
      available = versions(@registry.call(name), name)
      return if available.empty?

      previous = successful_versions(name)
      attempted = ResultStore.read(@results_dir).filter_map do |manifest|
        version = manifest.dig("gem", "version")
        version if manifest.dig("gem", "name") == name && Gem::Version.correct?(version) && ResultStore.mode_identity(manifest.dig("run", "mode")) == @mode
      end
      since = previous.max_by { |version| Gem::Version.new(version) } || attempted.min_by { |version| Gem::Version.new(version) } || available.last
      entry = state.dig("gems", name, @context) || {"since" => since, "observed" => previous}
      available.each do |version|
        next if Gem::Version.new(version) < Gem::Version.new(entry.fetch("since"))
        if entry.fetch("observed").include?(version)
          summary[:skipped] << {name:, version:}
          next
        end
        begin
          paths = Array(@dig.run(name, phase: "all", version:))
          errors = @dig.last_errors + @dig.last_observer_errors
          raise ArgumentError, errors.join("; ") unless errors.empty?
          raise ArgumentError, "observation did not produce successful install and require manifests" unless successful_versions(name).include?(version)

          entry["observed"] = (entry.fetch("observed") + [version]).uniq.sort_by { |value| Gem::Version.new(value) }
          (state.fetch("gems")[name] ||= {})[@context] = entry
          write_state(state)
          summary[:observed] << {name:, version:, paths:}
        rescue Gem::LoadError, StandardError => error
          summary[:errors] << {name:, version:, error: error.message}
        end
      end
    rescue => error
      summary[:errors] << {name:, version: nil, error: error.message}
    end

    def successful_versions(name)
      ResultStore.read(@results_dir).select do |manifest|
        manifest.dig("gem", "name") == name && Gem::Version.correct?(manifest.dig("gem", "version")) &&
          ResultStore.mode_identity(manifest.dig("run", "mode")) == @mode &&
          Gem::Platform.match_gem?(Gem::Platform.new(manifest.dig("gem", "platform") || "ruby"), name) &&
          manifest.fetch("errors").empty? && Array(manifest["observer_errors"]).empty? &&
          !manifest.dig("target", "timed_out") && !manifest.dig("target", "signal") &&
          [nil, 0].include?(manifest.dig("target", "exit_status"))
      end.group_by { |manifest| manifest.fetch("gem").values_at("version", "platform") }
        .filter_map do |(version, _platform), manifests|
        phases = %w[install require]
        phases << "plugin" if manifests.any? { |manifest| manifest.dig("gem", "rubygems_plugin") }
        phases << "bundler_plugin" if manifests.any? { |manifest| manifest.dig("gem", "bundler_plugin") }
        version if (phases - manifests.map { |manifest| manifest.fetch("phase") }).empty? && @dig.result_exists?(name, phase: "all", version:)
      end.uniq
    end

    def versions(response, name)
      raise ArgumentError, "invalid registry versions response for #{name}" unless response.is_a?(Array)

      unless response.all? do |entry|
        entry.is_a?(Hash) && entry["number"].is_a?(String) && Gem::Version.correct?(entry["number"]) &&
            %w[prerelease yanked].all? { |key| !entry.key?(key) || [true, false].include?(entry[key]) } &&
            (!entry.key?("platform") || entry["platform"].is_a?(String))
      end
        raise ArgumentError, "invalid registry versions response for #{name}"
      end
      response.filter_map do |entry|
        version = Gem::Version.new(entry.fetch("number"))
        next if entry["yanked"] || entry["prerelease"] || version.prerelease?
        next unless Gem::Platform.match_gem?(Gem::Platform.new(entry.fetch("platform", "ruby")), name)

        entry.fetch("number")
      end.uniq.sort_by { |version| Gem::Version.new(version) }
    end

    def registry_versions(name)
      uri = URI("https://rubygems.org/api/v1/versions/#{URI.encode_www_form_component(name)}.json")
      body = +""
      Timeout.timeout(30) do
        Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 5, read_timeout: 10) do |http|
          http.request_get(uri.request_uri, "Accept" => "application/json") do |response|
            raise ArgumentError, "registry returned HTTP #{response.code} for #{name}" unless response.is_a?(Net::HTTPSuccess)

            response.read_body do |chunk|
              raise ArgumentError, "registry response exceeds #{RESPONSE_LIMIT} bytes" if body.bytesize + chunk.bytesize > RESPONSE_LIMIT

              body << chunk
            end
          end
        end
      end
      JSON.parse(body)
    rescue JSON::ParserError => error
      raise ArgumentError, "invalid registry JSON: #{error.message}"
    end

    def load_state
      raise ArgumentError, "monitor state cannot be a symlink" if File.symlink?(@state_path)
      return {"schema_version" => 1, "gems" => {}} unless File.exist?(@state_path)

      state = JSON.parse(File.read(@state_path))
      unless state.is_a?(Hash) && state["schema_version"] == 1 && state["gems"].is_a?(Hash) && state["gems"].all? do |name, contexts|
        ResultStore::COMPONENT.match?(name) && contexts.is_a?(Hash) && contexts.all? do |context, entry|
          context.match?(/\A[0-9a-f]{64}\z/) && entry.is_a?(Hash) && entry["since"].is_a?(String) && Gem::Version.correct?(entry["since"]) &&
              entry["observed"].is_a?(Array) && entry["observed"].all? { |version| version.is_a?(String) && Gem::Version.correct?(version) }
        end
      end
        raise ArgumentError, "invalid monitor state"
      end
      state
    rescue JSON::ParserError => error
      raise ArgumentError, "invalid monitor state JSON: #{error.message}"
    end

    def write_state(state)
      raise ArgumentError, "monitor state cannot be a symlink" if File.symlink?(@state_path)

      Tempfile.create([".monitor-", ".tmp"], File.dirname(@state_path)) do |file|
        file.write(JSON.pretty_generate(state) << "\n")
        file.flush
        file.fsync
        File.rename(file.path, @state_path)
      end
    end
  end
end
