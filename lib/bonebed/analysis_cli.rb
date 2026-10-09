# frozen_string_literal: true

require "optparse"
require "cgi"
require "net/http"
require "tempfile"
require_relative "manifest_diff"
require_relative "policy"
require_relative "capability_lock"
require_relative "sarif"
require_relative "result_store"
require_relative "command_runner"
require_relative "static_analysis"

module Bonebed
  class CLI
    def self.static(arguments)
      options = {}
      parser = OptionParser.new do |parser|
        parser.banner = "Usage: bonebed static PATH [--manifest FILE]"
        parser.on("-h", "--help") { options[:help] = true }
        parser.on("--manifest FILE") { |value| options[:manifest] = value }
      end
      parser.parse!(arguments)
      if options[:help]
        puts parser
        return EXIT_OK
      end
      raise ArgumentError, "static requires one Ruby file or source directory" unless arguments.one?

      manifest = read_manifest(options[:manifest]) if options[:manifest]
      result = StaticAnalysis.call(arguments.first, manifest:)
      puts JSON.pretty_generate(result)
      return EXIT_OBSERVER_FAILED unless result["available"]

      result["errors"].empty? ? EXIT_OK : EXIT_TARGET_FAILED
    end

    def self.run_command(arguments)
      separator = arguments.index("--")
      if !separator && arguments.any? { |argument| %w[-h --help].include?(argument) }
        puts "Usage: bonebed run [--results DIR] [--timeout SECONDS] [options] -- COMMAND [ARGUMENTS...]"
        return EXIT_OK
      end
      raise ArgumentError, "run requires -- before the command" unless separator

      flags = arguments.take(separator)
      command = arguments.drop(separator + 1)
      options = {results_dir: "results", timeout: 60, offline: false, env_profile: "dev"}
      options.merge!(analysis_policy({}).defaults.slice("offline", "env_profile").transform_keys(&:to_sym)) if File.file?(".bonebed.yml")
      parser = OptionParser.new do |parser|
        parser.banner = "Usage: bonebed run [options] -- COMMAND [ARGUMENTS...]"
        parser.on("-h", "--help") {
          puts parser
          return EXIT_OK
        }
        parser.on("--results DIR") { |value| options[:results_dir] = value }
        parser.on("--timeout SECONDS", Integer) { |value| options[:timeout] = value }
        parser.on("--offline") { options[:offline] = true }
        capture_options(parser, options)
      end
      parser.parse!(flags)
      raise ArgumentError, "run does not support --repeat or --jobs" if options.key?(:repeat) || options.key?(:jobs)
      raise ArgumentError, "unexpected arguments before --: #{flags.join(" ")}" unless flags.empty?
      raise ArgumentError, "command is required after --" if command.empty?

      runner = CommandRunner.new(**options.except(:strict))
      warn_host
      path = runner.run(command)
      puts path
      summarize(path)
      observation_status(runner.last_errors.empty?, runner.last_observer_errors, options[:strict])
    end

    def self.diff(arguments)
      options = {format: "md", counts: false}
      parser = analysis_parser("diff BEFORE.json AFTER.json [--format md|json] [--counts]", options)
      parser.on("--counts") { options[:counts] = true }
      parser.parse!(arguments)
      return EXIT_OK if options[:help]
      raise ArgumentError, "diff requires two manifest files" unless arguments.size == 2

      before, after = arguments.map { |path| read_manifest(path) }
      output_diff([compare_manifests(before, after, counts: options[:counts])], options[:format])
      EXIT_OK
    end

    def self.check(arguments)
      options = {format: "md"}
      parser = analysis_parser("check RESULTS [--policy FILE] [--fail-on high] [--lock [FILE]]", options, formats: %w[md json csv html sarif])
      policy_options(parser, options)
      parser.on("--lock [FILE]") { |value| options[:lock] = value || "Gemfile.capabilities.lock" }
      parser.on("--gemfile FILE") { |value| options[:gemfile] = value }
      parser.on("--strict") { options[:strict] = true }
      parser.parse!(arguments)
      return EXIT_OK if options[:help]
      raise ArgumentError, "check requires a results directory or manifest" unless arguments.one?

      policy = analysis_policy(options)
      approved = read_capability_lock(options[:lock]) if options[:lock]
      manifests = analysis_manifests(arguments.first)
      threshold = options[:fail_on] || policy.defaults.fetch("fail_on")
      raise ArgumentError, "invalid severity: #{threshold}" unless Policy::SEVERITIES.include?(threshold)

      failed = false
      evaluated = manifests.map do |manifest|
        findings = policy.findings(manifest)
        if approved
          keys = approved.dig("gems", manifest.dig("gem", "name"), "phases", manifest.fetch("phase")) || []
          findings += (CapabilityKeys.call(manifest) - keys).map { |key| added_finding(key) }
        end
        failed ||= findings.any? { |finding| !finding["allowed"] && Policy::SEVERITIES.index(finding.fetch("severity")) >= Policy::SEVERITIES.index(threshold) }
        manifest.merge("findings" => findings)
      end
      puts format_report(evaluated, options[:format], lockfile: options[:gemfile])
      status = observation_exit(manifests, strict: options[:strict])
      return status unless status == EXIT_OK

      failed ? EXIT_POLICY_VIOLATION : EXIT_OK
    end

    def self.compare(arguments)
      options = observation_defaults
      parser = analysis_parser("compare GEM BEFORE_VERSION AFTER_VERSION [options]", options)
      observation_options(parser, options)
      parser.on("--counts") { options[:counts] = true }
      parser.parse!(arguments)
      return EXIT_OK if options[:help]
      raise ArgumentError, "compare requires GEM and two versions" unless arguments.size == 3

      name, before_version, after_version = arguments
      before = observe_cached(name, before_version, options)
      after = observe_cached(name, after_version, options)
      output_diff(compare_phases(before, after, counts: options[:counts]), options[:format])
      observation_exit(before + after)
    end

    def self.diff_lock(arguments)
      options = observation_defaults
      parser = analysis_parser("diff-lock BASE_LOCK HEAD_LOCK [options]", options)
      observation_options(parser, options)
      parser.on("--counts") { options[:counts] = true }
      parser.parse!(arguments)
      return EXIT_OK if options[:help]
      raise ArgumentError, "diff-lock requires two Gemfile.lock paths" unless arguments.size == 2

      before_entries, after_entries = arguments.map { |path| Survey.lockfile(path).to_h { |entry| [entry.fetch(:name), entry.fetch(:version)] } }
      observed = []
      changes = (before_entries.keys | after_entries.keys).sort.flat_map do |name|
        next [] if before_entries[name] == after_entries[name]

        before = before_entries[name] ? observe_cached(name, before_entries[name], options) : []
        after = after_entries[name] ? observe_cached(name, after_entries[name], options) : []
        observed.concat(before + after)
        compare_phases(before, after, counts: options[:counts])
      end
      output_diff(changes, options[:format], lockfile: arguments.last)
      observation_exit(observed)
    end

    def self.lock(arguments)
      options = observation_defaults.merge(gemfile: "Gemfile.lock", output: "Gemfile.capabilities.lock")
      parser = analysis_parser("lock [--gemfile FILE] [--output FILE] [--update GEM] [options]", options)
      observation_options(parser, options)
      parser.on("--gemfile FILE") { |value| options[:gemfile] = value }
      parser.on("--output FILE") { |value| options[:output] = value }
      parser.on("--update GEM") { |value| options[:update] = value }
      parser.parse!(arguments)
      return EXIT_OK if options[:help]
      raise ArgumentError, "unexpected arguments: #{arguments.join(" ")}" unless arguments.empty?

      entries = Survey.lockfile(options[:gemfile])
      approvals = options[:update] ? read_capability_lock(options[:output]) : {"version" => 1, "gems" => {}}
      if options[:update]
        entries = entries.select { |entry| entry.fetch(:name) == options[:update] }
        raise ArgumentError, "gem is not in the lockfile: #{options[:update]}" if entries.empty?
      end
      observations = entries.flat_map { |entry| observe_cached(entry.fetch(:name), entry.fetch(:version), options) }
      status = observation_exit(observations, strict: true)
      return status unless status == EXIT_OK

      expected_versions = entries.to_h { |entry| [entry.fetch(:name), entry.fetch(:version).to_s] }
      raise ArgumentError, "missing observations for capability lock" unless expected_versions.keys.sort == observations.map { |manifest| manifest.dig("gem", "name") }.uniq.sort

      observations.group_by { |manifest| manifest.dig("gem", "name") }.each do |name, manifests|
        version = expected_versions.fetch(name)
        raise ArgumentError, "observation version does not match lockfile for #{name}" unless manifests.all? { |manifest| manifest.dig("gem", "version") == version }

        phases = manifests.group_by { |manifest| manifest.fetch("phase") }.transform_values do |samples|
          samples.flat_map { |manifest| CapabilityKeys.call(manifest) }.uniq.sort
        end
        approvals["gems"][name] = {"version" => version, "phases" => phases}
      end
      atomic_yaml(options[:output], approvals)
      puts options[:output]
      EXIT_OK
    end

    def self.history(arguments)
      options = observation_defaults.merge(last: 5)
      parser = analysis_parser("history GEM [--last N] [options]", options)
      observation_options(parser, options)
      parser.on("--last N", Integer) { |value| options[:last] = value }
      parser.parse!(arguments)
      return EXIT_OK if options[:help]
      raise ArgumentError, "history requires one gem and --last between 2 and 100" unless arguments.one? && (2..100).cover?(options[:last])

      name = arguments.first
      raise ArgumentError, "invalid gem name" unless name.match?(Gem::Specification::VALID_NAME_PATTERN) && name.match?(/[a-zA-Z]/) && !name.start_with?(".", "-", "_")

      uri = URI("https://rubygems.org/api/v1/versions/#{URI.encode_www_form_component(name)}.json")
      response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 10, read_timeout: 30) { |http| http.get(uri.request_uri) }
      raise Error, "RubyGems versions returned HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

      versions = JSON.parse(response.body)
      raise Error, "invalid RubyGems versions response" unless versions.is_a?(Array) && versions.all? { |entry| entry.is_a?(Hash) && entry["number"].is_a?(String) && Gem::Version.correct?(entry["number"]) }

      versions = versions.map { |entry| entry.fetch("number") }.uniq.sort_by { |version| Gem::Version.new(version) }.last(options[:last])
      observations = versions.map { |version| observe_cached(name, version, options) }
      changes = observations.each_cons(2).flat_map { |before, after| compare_phases(before, after) }
      output_diff(changes, options[:format])
      observation_exit(observations.flatten)
    rescue JSON::ParserError => error
      raise Error, "invalid RubyGems versions response: #{error.message}"
    end

    def self.format_report(manifests, format, policy: nil, lockfile: nil)
      return JSON.pretty_generate(manifests) if format == "json"
      return JSON.pretty_generate(Sarif.call(manifests, policy:, lockfile:)) if format == "sarif"

      rows = manifests.flat_map do |manifest|
        findings = policy ? policy.findings(manifest) : manifest.fetch("findings") { Policy.new.findings(manifest) }
        findings = [{"capability" => "none", "severity" => "", "rule_id" => "", "allowed" => false}] if findings.empty?
        findings.map { |finding| [manifest.dig("gem", "name"), manifest.dig("gem", "version"), manifest["phase"], finding["capability"], finding["rule_id"], finding["severity"], finding["allowed"]] }
      end
      headers = %w[gem version phase capability rule severity allowed]
      case format
      when "csv"
        ([headers] + rows).map do |row|
          row.map do |value|
            text = value.to_s
            text = "'#{text}" if text.match?(/\A[=+\-@\t\r\n]/)
            "\"#{text.gsub('"', '""')}\""
          end.join(",")
        end.join("\r\n") << "\r\n"
      when "html"
        table = rows.map { |row| "<tr>#{row.map { |value| "<td>#{CGI.escapeHTML(value.to_s)}</td>" }.join}</tr>" }.join("\n")
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Bonebed findings</title><body><table><caption>Observed gem capabilities</caption><thead><tr>#{headers.map { |header| "<th scope=\"col\">#{header}</th>" }.join}</tr></thead><tbody>#{table}</tbody></table></body></html>"
      when "md"
        (["| #{headers.join(" | ")} |", "| #{headers.map { "---" }.join(" | ")} |"] + rows.map { |row| "| #{row.map { |value| markdown_cell(value) }.join(" | ")} |" }).join("\n")
      else
        raise ArgumentError, "format must be md, json, csv, html, or sarif"
      end
    end

    def self.analysis_parser(usage, options, formats: %w[md json sarif])
      OptionParser.new do |parser|
        parser.banner = "Usage: bonebed #{usage}"
        parser.on("-h", "--help") {
          puts parser
          options[:help] = true
        }
        parser.on("--format FORMAT", formats) { |value| options[:format] = value }
      end
    end

    def self.observation_defaults
      {format: "md", phase: "all", results_dir: "results", offline: false}
    end

    def self.observation_options(parser, options)
      parser.on("--results DIR") { |value| options[:results_dir] = value }
      parser.on("--phase PHASE", Dig::PHASES) { |value| options[:phase] = value }
      parser.on("--offline") { options[:offline] = true }
      parser.on("--timeout SECONDS", Integer) do |value|
        raise ArgumentError, "timeout must be positive" unless value.positive?

        options[:timeout] = value
      end
    end

    def self.policy_options(parser, options)
      parser.on("--policy FILE") { |value| options[:policy] = value }
      parser.on("--fail-on SEVERITY") { |value| options[:fail_on] = value }
    end

    def self.analysis_policy(options)
      Policy.load(options[:policy] || (".bonebed.yml" if File.file?(".bonebed.yml")))
    end

    def self.read_manifest(path)
      manifest = JSON.parse(File.read(path))
      raise ArgumentError, "invalid manifest: #{path}" unless ResultStore.valid?(manifest)

      manifest
    rescue JSON::ParserError => error
      raise ArgumentError, "invalid manifest #{path}: #{error.message}"
    end

    def self.analysis_manifests(path)
      return [read_manifest(path)] unless File.directory?(path)

      paths = ResultStore.paths(path)
      raise ArgumentError, "no manifests in #{path}" if paths.empty?

      paths.each { |file| read_manifest(file) }
      ResultStore.read(path)
    end

    def self.observe_cached(name, version, options)
      dig = Dig.new(**options.slice(:results_dir, :offline, :timeout, :env_profile, :writes_only, :real_home, :cwd, :enforce), quiet_target: true)
      mode = dig.observation_mode
      store = ResultStore.new(options[:results_dir])
      if options[:phase] == "all"
        store.matching(name, phase: "install", version:, mode:).each do |installed|
          gem = installed.fetch("gem")
          phases = gem["rubygems_plugin"] ? %w[require plugin] : %w[require]
          cached = phases.flat_map { |phase| store.matching(name, phase:, version:, platform: gem["platform"], mode:) }
          return [installed, *cached] if (phases - cached.map { |manifest| manifest.fetch("phase") }).empty?
        end
      else
        cached = store.matching(name, phase: options[:phase], version:, mode:)
        if options[:phase] == "exec"
          cached = cached.select do |manifest|
            executable = manifest.dig("run", "executable")
            executable.is_a?(String) && manifest.dig("gem", "executables") == [executable] && manifest.dig("run", "arguments") == []
          end
        end
        return cached unless cached.empty?
      end

      warn_host
      Array(dig.run(name, phase: options[:phase], version:)).map { |path| read_manifest(path) }
    end

    def self.observation_success?(manifest)
      manifest.fetch("errors", []).empty? && !manifest.dig("target", "timed_out") && !manifest.dig("target", "signal") && [nil, 0].include?(manifest.dig("target", "exit_status"))
    end

    def self.observation_exit(manifests, strict: false)
      manifests.each { |manifest| manifest.fetch("errors", []).each { |error| warn error } }
      observation_status(manifests.all? { |manifest| observation_success?(manifest) }, manifests.flat_map { |manifest| manifest["observer_errors"] || [] }, strict)
    end

    def self.compare_manifests(before, after, counts: false)
      manifest = after || before
      empty = {"schema_version" => 2}
      {"gem" => manifest.dig("gem", "name"), "phase" => manifest.fetch("phase"),
       "before_version" => before&.dig("gem", "version"), "after_version" => after&.dig("gem", "version")}
        .merge(ManifestDiff.call(before || empty, after || empty, counts:))
    end

    def self.compare_phases(before, after, counts: false)
      previous = before.to_h { |manifest| [manifest.fetch("phase"), manifest] }
      current = after.to_h { |manifest| [manifest.fetch("phase"), manifest] }
      (previous.keys | current.keys).sort.map { |phase| compare_manifests(previous[phase], current[phase], counts:) }
    end

    def self.output_diff(changes, format, lockfile: nil)
      case format
      when "json"
        puts JSON.pretty_generate(changes)
      when "md"
        puts "# Capability diff"
        changes.each do |change|
          puts "\n## #{markdown_cell(change.fetch("gem"))} (#{markdown_cell(change.fetch("phase"))})"
          %w[added removed].each { |kind| puts "\n#{kind.capitalize}: #{change.fetch(kind).empty? ? "none" : change.fetch(kind).map { |key| markdown_cell(key) }.join(", ")}" }
          puts "\nCounts: #{markdown_cell(JSON.generate(change["counts"]))}" if change["counts"]
        end
      when "sarif"
        manifests = changes.map do |change|
          {"gem" => {"name" => change.fetch("gem"), "version" => change["after_version"] || change["before_version"]},
           "phase" => change.fetch("phase"), "findings" => change.fetch("added").map { |key| added_finding(key) }}
        end
        puts JSON.pretty_generate(Sarif.call(manifests, lockfile:))
      else
        raise ArgumentError, "diff format must be md, json, or sarif"
      end
    end

    def self.added_finding(key)
      {"rule_id" => "capability-added", "severity" => "high", "message" => "Capability is not in the approved set", "capability" => key, "allowed" => false}
    end

    def self.read_capability_lock(path)
      CapabilityLock.load(path)
    end

    def self.atomic_yaml(path, data)
      directory = File.dirname(File.expand_path(path))
      FileUtils.mkdir_p(directory)
      Tempfile.create([".bonebed-lock-", ".tmp"], directory) do |file|
        file.write(YAML.dump(data))
        file.flush
        file.fsync
        File.rename(file.path, path)
      end
    end

    def self.markdown_cell(value)
      CGI.escapeHTML(value.to_s).gsub("|", "\\|").gsub("`", "&#96;").gsub(/\s+/, " ")
    end
  end
end
