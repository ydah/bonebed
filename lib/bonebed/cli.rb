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

    def self.start(arguments = ARGV)
      case arguments.shift
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
      when "report"
        report(arguments)
      when nil, "help", "--help", "-h"
        puts <<~HELP
          Usage:
            bonebed --version
            bonebed doctor
            bonebed baseline [--refresh]
            bonebed dig GEM [--phase require|install] [--require PATH] [--version VERSION] [--offline]
            bonebed dig --gemfile Gemfile.lock [--phase require|install]
            bonebed survey (--top N | --file FILE | --gemfile FILE) [--phase require|install]
            bonebed report RESULTS_DIR [--format md]
        HELP
        EXIT_OK
      else
        warn "Unknown command. Run `bonebed help` for usage."
        EXIT_USAGE
      end
    rescue OptionParser::ParseError, ArgumentError => error
      warn error.message
      EXIT_USAGE
    rescue Gem::LoadError, Error, SystemCallError => error
      warn error.message
      EXIT_TARGET_FAILED
    end

    def self.dig(arguments)
      options = {phase: "require", results_dir: "results", timeout: nil, offline: false, gemfile: nil, require_path: nil}
      OptionParser.new do |parser|
        parser.banner = "Usage: bonebed dig GEM [options]\n       bonebed dig --gemfile FILE [options]"
        parser.on("-h", "--help", "Show this help") {
          puts parser
          return EXIT_OK
        }
        parser.on("--phase PHASE") { |value| options[:phase] = value }
        parser.on("--require PATH") { |value| options[:require_path] = value }
        parser.on("--version VERSION") { |value| options[:version] = value }
        parser.on("--results DIR") { |value| options[:results_dir] = value }
        parser.on("--timeout SECONDS", Integer) { |value| options[:timeout] = value }
        parser.on("--offline") { options[:offline] = true }
        parser.on("--gemfile FILE") { |value| options[:gemfile] = value }
        capture_options(parser, options)
      end.parse!(arguments)
      name = arguments.shift
      raise ArgumentError, "unexpected arguments: #{arguments.join(" ")}" unless arguments.empty?
      raise ArgumentError, "phase must be require or install" unless Dig::PHASES.include?(options[:phase])

      dig = Dig.new(**options.slice(:results_dir, :timeout, :offline, :quiet_target, :output_limit, :argv_limit))
      if options[:gemfile]
        raise ArgumentError, "GEM cannot be combined with --gemfile" if name
        raise ArgumentError, "--require cannot be combined with --gemfile" if options[:require_path]
        raise ArgumentError, "--version cannot be combined with --gemfile" if options[:version]

        warn_host
        survey = Survey.new(dig:, isolate: true)
        success = survey.run(Survey.lockfile(options[:gemfile]), phase: options[:phase])
        observation_status(success, survey.last_observer_errors, options[:strict])
      else
        warn_host
        path = dig.run(name, phase: options[:phase], version: options[:version], require_path: options[:require_path])
        puts path
        summarize(path)
        observation_status(dig.last_errors.empty?, dig.last_observer_errors, options[:strict])
      end
    end

    def self.survey(arguments)
      options = {phase: "install", results_dir: "results", timeout: nil, offline: false}
      OptionParser.new do |parser|
        parser.banner = "Usage: bonebed survey (--top N | --file FILE | --gemfile FILE) [options]"
        parser.on("-h", "--help", "Show this help") {
          puts parser
          return EXIT_OK
        }
        parser.on("--top N", Integer) { |value| options[:top] = value }
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
      raise ArgumentError, "phase must be require or install" unless Dig::PHASES.include?(options[:phase])

      entries = if options[:top]
        Survey.top(options[:top])
      else
        options[:file] ? Survey.file(options[:file]) : Survey.lockfile(options[:gemfile])
      end
      dig = Dig.new(**options.slice(:results_dir, :timeout, :offline, :quiet_target, :output_limit, :argv_limit))
      warn_host
      survey = Survey.new(dig:, isolate: true)
      success = survey.run(entries, phase: options[:phase])
      observation_status(success, survey.last_observer_errors, options[:strict])
    end

    def self.report(arguments)
      format = "md"
      OptionParser.new do |parser|
        parser.banner = "Usage: bonebed report RESULTS_DIR [--format md]"
        parser.on("-h", "--help", "Show this help") {
          puts parser
          return EXIT_OK
        }
        parser.on("--format FORMAT") { |value| format = value }
      end.parse!(arguments)
      raise ArgumentError, "format must be md" unless format == "md"
      raise ArgumentError, "results directory is required" unless arguments.one?

      puts Report.new(arguments.first).markdown
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
      parser.on("--strict", "Fail on observer errors (exit 2)") { options[:strict] = true }
      parser.on("--quiet-target", "Capture target output without streaming it") { options[:quiet_target] = true }
      parser.on("--output-limit BYTES", Integer, "Capture limit per output stream (default: 1048576)") { |value| options[:output_limit] = value }
      parser.on("--argv-limit N", Integer, "Maximum captured arguments (default: 64)") { |value| options[:argv_limit] = value }
    end

    def self.warn_host
      warn "Warning: running target code on the host; only observe trusted gems. Use a disposable container for untrusted gems." unless Doctor.container?
    end

    def self.observation_status(success, observer_errors, strict)
      observer_errors.each { |error| warn "Warning: observer: #{error}" }
      return EXIT_TARGET_FAILED unless success

      (strict && !observer_errors.empty?) ? EXIT_OBSERVER_FAILED : EXIT_OK
    end

    def self.summarize(path)
      manifest = JSON.parse(File.read(path))
      gem = manifest.fetch("gem")
      warn format("%s %s (%s)  %.1fs", gem.fetch("name"), gem.fetch("version"), manifest.fetch("phase"), manifest.dig("stats", "wall_ms").to_f / 1000)
      {"network" => manifest.fetch("network").size, "exec" => manifest.fetch("exec").size,
       "notable" => manifest.fetch("files").fetch("notable").size}.each do |label, count|
        warn format("  %-9s %s", label, count.zero? ? "none" : count)
      end
      warn "  manifest  #{path}"
    end
  end
end
