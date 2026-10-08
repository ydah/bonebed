# frozen_string_literal: true

require "digest"
require "rbconfig"
require_relative "difference"
require_relative "sensitive_path"
require_relative "result_store"

module Bonebed
  module ManifestBuilder
    ROUTINE_RUBYGEMS_PREFIXES = %w[$HOME/.cache/gem/ $HOME/.local/share/gem/].freeze
    RESOLVER_PATHS = %w[/etc/resolv.conf /etc/hosts /etc/host.conf /etc/nsswitch.conf /etc/gai.conf].freeze

    module_function

    def call(name, version, phase, observation, baseline, platform: nil, require_path: nil,
      specifications: [], package: nil, run: nil)
      observation = Difference.call(observation, baseline.observation)
      files = observation.fetch(:files).transform_values { |entries| entries.keys.sort }
      reads = files.fetch(:read)
      own = "$GEM_HOME/gems/#{name}-#{version}#{"-#{platform}" if platform && platform != "ruby"}/"
      files[:read] = {self: reads.select { |path| path.start_with?(own) }, resolver: reads & RESOLVER_PATHS,
                     other: reads.reject { |path| path.start_with?(own) || RESOLVER_PATHS.include?(path) }}
      observation.fetch(:changes, {}).each do |event, count|
        operation = event.fetch(:operation).to_sym
        files[:write] |= [event.fetch(:path)] if %i[write create truncate append rw].include?(operation)
        unless operation == :write
          (files[operation] ||= []) << event.except(:operation).merge(count:)
        end
      end
      files[:notable] = (reads.grep(/\A(?:\$HOME|\$PWD)\//) + files[:write].grep(/\A(?:\$HOME|\$PWD|\$TMPDIR)\//)).uniq.sort
        .reject { |path| ROUTINE_RUBYGEMS_PREFIXES.any? { |prefix| path.start_with?(prefix) } }
      specification = specifications.find { |spec| spec.name == name }
      gem = {"name" => name, "version" => version, "platform" => platform, "require_path" => require_path,
             "sha256" => package && Digest::SHA256.file(package).hexdigest,
             "extensions" => specification&.extensions || [], "executables" => specification&.executables || [],
             "required_ruby_version" => specification&.required_ruby_version&.to_s,
             "post_install_message" => specification&.post_install_message,
             "rubygems_plugin" => !!specification&.files&.any? { |file| File.basename(file) == "rubygems_plugin.rb" }}
      stats = observation.fetch(:stats).transform_keys(&:to_s)
      stats["open_total"] = stats.delete("openat_total")
      stats["open_after_baseline"] = stats.delete("openat_after_baseline")
      data = {
        "schema_version" => 2, "tool" => {"name" => "bonebed", "version" => VERSION,
                                          "seccomp_notify" => Gem.loaded_specs["seccomp-notify"]&.version&.to_s},
        "run" => run, "started_at" => observation[:started_at], "gem" => gem, "phase" => phase,
        "environment" => {"ruby" => RUBY_VERSION, "arch" => RbConfig::CONFIG.fetch("host_cpu"), "kernel" => `uname -r`.strip, "baseline_id" => baseline.id},
        "target" => observation[:target] || {exit_status: nil, signal: nil, timed_out: false},
        "files" => files, "network" => counted(observation.fetch(:network)), "exec" => counted(observation.fetch(:exec)),
        "threads" => counted(observation.fetch(:threads, {})), "stats" => stats,
        "dependencies" => specifications.reject { |spec| spec.name == name }.map { |spec| {"name" => spec.name, "version" => spec.version.to_s} }.sort_by { |spec| spec["name"] },
        "errors" => observation.fetch(:errors), "observer_errors" => observation.fetch(:observer_errors, []),
        "stdout" => observation.fetch(:stdout, ""), "stderr" => observation.fetch(:stderr, ""),
        "stdout_truncated" => observation.fetch(:stdout_truncated, false), "stderr_truncated" => observation.fetch(:stderr_truncated, false),
        "canary_hits" => [], "findings" => []
      }
      data = JSON.parse(JSON.generate(data))
      data["process_tree"] = observation.fetch(:process_tree, [])
      data["run"]["mode"]["isolation"] = observation[:isolation] if data["run"] && observation[:isolation]
      %i[processes listen sockets suspicious dns anti_analysis].each do |group|
        data[group.to_s] = counted(observation.fetch(group, {}))
      end
      data["anti_analysis"] |= reads.grep(%r{\A/proc/(?:self|<pid>)/(?:status|maps|environ)\z}).map { |path| {"path" => path} }
      data["capabilities"] = capabilities(data)
      data
    end

    def counted(entries)
      entries.map { |event, count| event.transform_keys(&:to_s).merge("count" => count) }.sort_by(&:to_s)
    end

    def capabilities(data)
      ResultStore.capabilities(data)
    end
  end
end
