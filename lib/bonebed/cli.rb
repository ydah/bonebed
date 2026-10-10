# frozen_string_literal: true

require "bonebed"
require "optparse"

module Bonebed
  class CLI
    EXIT_OK = 0
    EXIT_TARGET_FAILED = 1
    EXIT_OBSERVER_FAILED = 2
    EXIT_POLICY_VIOLATION = 3
    EXIT_USAGE = 64
    EXECUTION_OPTIONS = %i[verbose require_container allow_host].freeze

    def self.start(arguments = ARGV)
      command = arguments.shift
      case command
      when "--docker"
        require_relative "docker_runner"
        DockerRunner.new.run(arguments)
      when "--version", "-v", "version"
        raise ArgumentError, "unexpected arguments: #{arguments.join(" ")}" unless arguments.empty?

        puts VERSION
        EXIT_OK
      when "doctor"
        doctor(arguments)
      when "baseline"
        baseline(arguments)
      when "dig"
        dig(arguments)
      when "survey"
        survey(arguments)
      when "migrate"
        if arguments == ["--help"] || arguments == ["-h"]
          puts "Usage: bonebed migrate RESULTS"
          return EXIT_OK
        end
        raise ArgumentError, "results directory is required" unless arguments.one?
        puts ResultStore.new(arguments.first).migrate
        EXIT_OK
      when "policy"
        if arguments == ["--help"] || arguments == ["-h"]
          puts "Usage: bonebed policy generate RESULTS"
          return EXIT_OK
        end
        raise ArgumentError, "usage: bonebed policy generate RESULTS" unless arguments.size == 2 && arguments.shift == "generate"
        puts YAML.dump(Enforcement.generate(ResultStore.read(arguments.first)))
        EXIT_OK
      when "dataset"
        require_relative "dataset"
        output = "site"
        sbom = nil
        OptionParser.new do |parser|
          parser.banner = "Usage: bonebed dataset RESULTS [--output DIR] [--sbom FILE]"
          parser.on("-h", "--help") {
            puts parser
            return EXIT_OK
          }
          parser.on("--output DIR") { |value| output = value }
          parser.on("--sbom FILE") { |value| sbom = value }
        end.parse!(arguments)
        raise ArgumentError, "usage: bonebed dataset RESULTS [--output DIR] [--sbom FILE]" unless arguments.one?

        dataset = Dataset.new(arguments.first)
        if sbom
          puts JSON.pretty_generate(dataset.augment_sbom(JSON.parse(File.read(sbom))))
        else
          puts dataset.write(output)
        end
        EXIT_OK
      when "monitor"
        monitor(arguments)
      when "bundle"
        observe_bundle(arguments)
      when "run"
        run_command(arguments)
      when "static"
        static(arguments)
      when "diff", "check", "compare", "diff-lock", "lock", "history"
        public_send(command.tr("-", "_"), arguments)
      when "report"
        report(arguments)
      when nil, "help", "--help", "-h"
        puts <<~HELP
          Usage:
            bonebed --version
            bonebed doctor
            bonebed baseline [--refresh]
            bonebed dig GEM [--phase require|install|plugin|bundler_plugin|exec|all] [--require PATH] [--version VERSION] [--offline]
            bonebed dig --gemfile Gemfile.lock [--phase all]
            bonebed survey (--top N | --file FILE | --gemfile FILE) [--phase all] [--jobs N]
            bonebed run [options] -- COMMAND [ARGS...]
            bonebed bundle [--gemfile Gemfile] [--offline]
            bonebed static PATH [--manifest FILE]
            bonebed diff BEFORE.json AFTER.json [--format md|json|sarif]
            bonebed compare GEM VERSION_A VERSION_B
            bonebed diff-lock BASE.lock HEAD.lock
            bonebed history GEM [--last N]
            bonebed check RESULTS [--policy FILE] [--lock]
            bonebed lock [--gemfile FILE] [--update GEM]
            bonebed report RESULTS [--format md|json|html|csv|sarif]
            bonebed policy generate RESULTS
            bonebed migrate RESULTS
            bonebed dataset RESULTS [--output DIR] [--sbom FILE]
            bonebed monitor --file GEMS [--results DIR] [--state FILE]
            bonebed --docker COMMAND [--ruby 3.3,3.4,4.0] [OPTIONS]
        HELP
        EXIT_OK
      else
        warn "Unknown command. Run `bonebed help` for usage."
        EXIT_USAGE
      end
    rescue OptionParser::ParseError, ArgumentError => error
      warn error.message
      EXIT_USAGE
    rescue ObserverError => error
      warn error.message
      EXIT_OBSERVER_FAILED
    rescue Gem::LoadError, Error, SystemCallError => error
      warn error.message
      EXIT_TARGET_FAILED
    end

    def self.monitor(arguments)
      require_relative "monitor"
      options = {results_dir: "results", state: ".bonebed/monitor.json"}.merge(execution_defaults)
      OptionParser.new do |parser|
        parser.banner = "Usage: bonebed monitor --file GEMS [--results DIR] [--state FILE]"
        parser.on("-h", "--help") {
          puts parser
          return EXIT_OK
        }
        parser.on("--file FILE") { |value| options[:file] = value }
        parser.on("--results DIR") { |value| options[:results_dir] = value }
        parser.on("--state FILE") { |value| options[:state] = value }
        parser.on("--timeout SECONDS", Integer) { |value| options[:timeout] = value }
        execution_options(parser, options)
      end.parse!(arguments)
      raise ArgumentError, "--file is required and positional arguments are not supported" unless options[:file] && arguments.empty?

      warn_host(options.merge(phase: "all", offline: true))
      names = Survey.file(options[:file]).map { |entry| entry.fetch(:name) }
      dig = Dig.new(results_dir: options[:results_dir], timeout: options[:timeout], offline: true, quiet_target: true)
      result = Monitor.new(results_dir: options[:results_dir], state_path: options[:state], dig:).run(names)
      puts JSON.pretty_generate(result)
      result[:errors].empty? ? EXIT_OK : EXIT_TARGET_FAILED
    end

    def self.observe_bundle(arguments)
      require_relative "bundle_runner"
      options = {gemfile: "Gemfile", results_dir: "results"}.merge(execution_defaults)
      options.merge!(Policy.load(".bonebed.yml").defaults.slice("offline", "env_profile").transform_keys(&:to_sym)) if File.file?(".bonebed.yml")
      OptionParser.new do |parser|
        parser.banner = "Usage: bonebed bundle [--gemfile FILE] [--lockfile FILE] [options]"
        parser.on("-h", "--help") do
          puts parser
          return EXIT_OK
        end
        parser.on("--gemfile FILE") { |value| options[:gemfile] = value }
        parser.on("--lockfile FILE") { |value| options[:lockfile] = value }
        parser.on("--results DIR") { |value| options[:results_dir] = value }
        parser.on("--timeout SECONDS", Integer) { |value| options[:timeout] = value }
        parser.on("--offline") { options[:offline] = true }
        capture_options(parser, options)
      end.parse!(arguments)
      raise ArgumentError, "bundle does not accept positional arguments, --jobs or --repeat" unless arguments.empty? && !options[:jobs] && !options[:repeat]

      warn_host(options.merge(phase: "install"))
      runner = BundleRunner.new(**options.except(:gemfile, :lockfile, :strict, *EXECUTION_OPTIONS))
      path = runner.run(**options.slice(:gemfile, :lockfile))
      puts path
      summarize(path, verbose: options[:verbose])
      observation_status(runner.last_errors.empty?, runner.last_observer_errors, options[:strict], fatal: runner.fatal_observer_error?)
    end

    def self.dig(arguments)
      separator = arguments.index("--")
      target_arguments = separator ? arguments.slice!(separator..).drop(1) : []
      options = {phase: "require", results_dir: "results", timeout: nil, offline: false, gemfile: nil, require_path: nil}.merge(execution_defaults)
      options.merge!(Policy.load(".bonebed.yml").defaults.slice("phase", "offline", "env_profile").transform_keys(&:to_sym)) if File.file?(".bonebed.yml")
      OptionParser.new do |parser|
        parser.banner = "Usage: bonebed dig GEM [options]\n       bonebed dig --gemfile FILE [options]"
        parser.on("-h", "--help", "Show this help") {
          puts parser
          return EXIT_OK
        }
        parser.on("--phase PHASE") { |value| options[:phase] = value }
        parser.on("--platform PLATFORM") { |value| options[:platform] = value }
        parser.on("--require PATH") { |value| options[:require_path] = value }
        parser.on("--version VERSION") { |value| options[:version] = value }
        parser.on("--executable NAME") { |value| options[:executable] = value }
        parser.on("--results DIR") { |value| options[:results_dir] = value }
        parser.on("--timeout SECONDS", Integer) { |value| options[:timeout] = value }
        parser.on("--offline") { options[:offline] = true }
        parser.on("--gemfile FILE") { |value| options[:gemfile] = value }
        capture_options(parser, options)
      end.parse!(arguments)
      name = arguments.shift
      raise ArgumentError, "unexpected arguments: #{arguments.join(" ")}" unless arguments.empty?
      raise ArgumentError, "phase must be #{Dig::PHASES.join(", ")}" unless Dig::PHASES.include?(options[:phase])
      raise ArgumentError, "executable arguments require --phase exec" if options[:phase] != "exec" && (separator || options[:executable])

      dig = Dig.new(**options.slice(:results_dir, :timeout, :offline, :sinkhole, :quiet_target, :output_limit, :argv_limit, :real_home, :cwd, :env_profile, :writes_only, :enforce, :deny, :trace, :repeat))
      if options[:gemfile]
        raise ArgumentError, "GEM cannot be combined with --gemfile" if name
        raise ArgumentError, "--require cannot be combined with --gemfile" if options[:require_path]
        raise ArgumentError, "--version cannot be combined with --gemfile" if options[:version]
        raise ArgumentError, "--executable and command arguments cannot be combined with --gemfile" if options[:executable] || separator

        warn_host(options)
        survey = Survey.new(dig:, isolate: true, jobs: options.fetch(:jobs, 1))
        success = survey.run(Survey.lockfile(options[:gemfile]), phase: options[:phase])
        observation_status(success, survey.last_observer_errors, options[:strict], fatal: survey.fatal_observer_error?, target_failed: survey.target_failed?)
      else
        warn_host(options)
        execution = (options[:phase] == "exec") ? {executable: options[:executable], arguments: target_arguments} : {}
        paths = Array(dig.run(name, phase: options[:phase], version: options[:version], require_path: options[:require_path], platform: options[:platform], **execution))
        paths.each do |path|
          puts path
          summarize(path, verbose: options[:verbose])
        end
        observation_status(dig.last_errors.empty?, dig.last_observer_errors, options[:strict])
      end
    end

    def self.survey(arguments)
      options = {phase: "install", results_dir: "results", timeout: nil, offline: false}.merge(execution_defaults)
      options.merge!(Policy.load(".bonebed.yml").defaults.slice("phase", "offline", "env_profile", "top_fallback").transform_keys(&:to_sym)) if File.file?(".bonebed.yml")
      OptionParser.new do |parser|
        parser.banner = "Usage: bonebed survey (--top N | --file FILE | --gemfile FILE) [options]"
        parser.on("-h", "--help", "Show this help") {
          puts parser
          return EXIT_OK
        }
        parser.on("--top N", Integer) { |value| options[:top] = value }
        parser.on("--top-fallback FILE", "Use a reviewed ranking snapshot if RubyGems stats fails") do |value|
          options[:top_fallback] = value
          options[:explicit_top_fallback] = true
        end
        parser.on("--file FILE") { |value| options[:file] = value }
        parser.on("--gemfile FILE") { |value| options[:gemfile] = value }
        parser.on("--phase PHASE") { |value| options[:phase] = value }
        parser.on("--results DIR") { |value| options[:results_dir] = value }
        parser.on("--timeout SECONDS", Integer) { |value| options[:timeout] = value }
        parser.on("--offline") { options[:offline] = true }
        capture_options(parser, options)
      end.parse!(arguments)
      raise ArgumentError, "unexpected arguments: #{arguments.join(" ")}" unless arguments.empty?
      raise ArgumentError, "choose exactly one of --top, --file, or --gemfile" unless options.values_at(:top, :file, :gemfile).compact.one?
      raise ArgumentError, "--top-fallback requires --top" if options[:explicit_top_fallback] && !options[:top]
      raise ArgumentError, "phase must be #{Dig::PHASES.join(", ")}" unless Dig::PHASES.include?(options[:phase])

      warn_host(options)
      entries = if options[:top]
        Survey.top(options[:top], fallback: options[:top_fallback])
      else
        options[:file] ? Survey.file(options[:file]) : Survey.lockfile(options[:gemfile])
      end
      dig = Dig.new(**options.slice(:results_dir, :timeout, :offline, :sinkhole, :quiet_target, :output_limit, :argv_limit, :real_home, :cwd, :env_profile, :writes_only, :enforce, :deny, :trace, :repeat))
      survey = Survey.new(dig:, isolate: true, jobs: options.fetch(:jobs, 1))
      success = survey.run(entries, phase: options[:phase])
      observation_status(success, survey.last_observer_errors, options[:strict], fatal: survey.fatal_observer_error?, target_failed: survey.target_failed?)
    end

    def self.report(arguments)
      format = "md"
      summary = false
      OptionParser.new do |parser|
        parser.banner = "Usage: bonebed report RESULTS_DIR [--format md|json|csv|html|sarif] [--summary]"
        parser.on("-h", "--help", "Show this help") {
          puts parser
          return EXIT_OK
        }
        parser.on("--format FORMAT") { |value| format = value }
        parser.on("--summary", "Stream aggregate counts as JSON") { summary = true }
      end.parse!(arguments)
      raise ArgumentError, "unsupported report format" unless %w[md json csv html sarif].include?(format)
      raise ArgumentError, "results directory is required" unless arguments.one?
      raise ArgumentError, "--summary emits JSON; use --format json or omit --format" if summary && !%w[md json].include?(format)

      if summary
        puts JSON.pretty_generate(Report.summary(arguments.first))
      else
        puts (format == "md") ? Report.new(arguments.first).markdown : format_report(ResultStore.read(arguments.first), format)
      end
      EXIT_OK
    end

    def self.baseline(arguments)
      refresh = false
      OptionParser.new do |parser|
        parser.banner = "Usage: bonebed baseline [--refresh]"
        parser.on("-h", "--help", "Show this help") {
          puts parser
          return EXIT_OK
        }
        parser.on("--refresh") { refresh = true }
      end.parse!(arguments)
      raise ArgumentError, "unexpected arguments: #{arguments.join(" ")}" unless arguments.empty?

      puts Baseline.new.capture(refresh:).id
      EXIT_OK
    end

    def self.doctor(arguments)
      OptionParser.new do |parser|
        parser.banner = "Usage: bonebed doctor"
        parser.on("-h", "--help", "Show this help") {
          puts parser
          return EXIT_OK
        }
      end.parse!(arguments)
      raise ArgumentError, "unexpected arguments: #{arguments.join(" ")}" unless arguments.empty?

      Doctor.new.run ? EXIT_OK : EXIT_TARGET_FAILED
    end

    def self.capture_options(parser, options)
      execution_options(parser, options)
      parser.on("--sinkhole", "Observe network intent with local sinkhole responses") { options[:sinkhole] = true }
      parser.on("--repeat N", Integer, "Observe 1 to 100 samples") { |value| options[:repeat] = value }
      parser.on("--enforce FILE", "Apply a Landlock policy") { |value| options[:enforce] = value }
      deny_option(parser, options)
      parser.on("--trace PREFIX", "Write decoded timeline JSONL per phase") { |value| options[:trace] = value }
      parser.on("--env-profile PROFILE", "dev, ci or prod") { |value| options[:env_profile] = value }
      parser.on("--writes-only", "Skip file read observations") { options[:writes_only] = true }
      parser.on("--jobs N", Integer, "Parallel survey workers") { |value| options[:jobs] = value }
      parser.on("--real-home", "Use the real home directory") { options[:real_home] = true }
      parser.on("--cwd DIR", "Use an explicit working directory") { |value| options[:cwd] = value }
      parser.on("--strict", "Fail on observer errors (exit 2)") { options[:strict] = true }
      parser.on("--quiet-target", "Capture target output without streaming it") { options[:quiet_target] = true }
      parser.on("--output-limit BYTES", Integer, "Capture limit per output stream (default: 1048576)") { |value| options[:output_limit] = value }
      parser.on("--argv-limit N", Integer, "Maximum captured arguments (default: 64)") { |value| options[:argv_limit] = value }
    end

    def self.deny_option(parser, options)
      parser.on("--deny FILE", "Best-effort policy refusal (not a security boundary)") do |value|
        options[:deny] = value
        warn "Warning: --deny is best-effort syscall refusal, not a security boundary; argument races and unobserved calls remain possible."
      end
    end

    def self.execution_defaults
      return {} unless File.file?(".bonebed.yml")

      Policy.load(".bonebed.yml").defaults.slice(*EXECUTION_OPTIONS.map(&:to_s)).transform_keys(&:to_sym)
    end

    def self.execution_options(parser, options)
      parser.on("--verbose", "Print observer diagnostics to stderr") { options[:verbose] = true }
      parser.on("--require-container", "Refuse target execution outside a container") { options[:require_container] = true }
      parser.on("--allow-host", "Explicitly override --require-container") { options[:allow_host] = true }
    end

    def self.warn_host(options = {})
      container = Doctor.container?
      if !container && options[:require_container] && !options[:allow_host]
        raise ObserverError, "Container required for target execution; use --docker or explicitly override with --allow-host."
      end
      warn "Warning: running target code on the host; only observe trusted gems. Use a disposable container for untrusted gems." unless container
      if options[:verbose]
        warn "Diagnostic: ruby=#{RUBY_VERSION} platform=#{RUBY_PLATFORM} container=#{container} phase=#{options.fetch(:phase, "command")} offline=#{!!options[:offline]} sinkhole=#{!!options[:sinkhole]}"
      end
    end

    def self.observation_status(success, observer_errors, strict, fatal: false, target_failed: !success)
      observer_errors.each { |error| warn "Warning: observer: #{error}" }
      return EXIT_TARGET_FAILED if target_failed

      (fatal || (strict && !observer_errors.empty?)) ? EXIT_OBSERVER_FAILED : EXIT_OK
    end

    def self.summarize(path, verbose: false)
      manifest = JSON.parse(File.read(path))
      gem = manifest.fetch("gem")
      warn format("%s %s (%s)  %.1fs", gem.fetch("name"), gem.fetch("version"), manifest.fetch("phase"), manifest.dig("stats", "wall_ms").to_f / 1000)
      {"network" => manifest.fetch("network").size, "exec" => manifest.fetch("exec").size,
       "notable" => manifest.fetch("files").fetch("notable").size}.each do |label, count|
        warn format("  %-9s %s", label, count.zero? ? "none" : count)
      end
      counts = Policy.new.findings(manifest).group_by { |finding| finding.fetch("severity") }.transform_values(&:size)
      severities = Policy::SEVERITIES.reverse.filter_map do |severity|
        next unless counts[severity]

        text = "#{severity}=#{counts.fetch(severity)}"
        if $stderr.tty? && !ENV.key?("NO_COLOR")
          color = {"critical" => "1;31", "high" => "31", "medium" => "33", "low" => "36", "info" => "37"}.fetch(severity)
          text = "\e[#{color}m#{text}\e[0m"
        end
        text
      end
      warn "  severity  #{severities.empty? ? "no matching rules" : severities.join(", ")}"
      warn "  manifest  #{path}"
      if verbose
        warn "Diagnostic: open_total=#{manifest.dig("stats", "open_total").to_i} observer_errors=#{Array(manifest["observer_errors"]).size} target_exit=#{manifest.dig("target", "exit_status").inspect} timed_out=#{!!manifest.dig("target", "timed_out")}"
      end
    end
  end
end

require_relative "analysis_cli"
