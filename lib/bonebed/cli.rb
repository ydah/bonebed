# frozen_string_literal: true

require "bonebed"
require "optparse"

module Bonebed
  class CLI
    def self.start(arguments = ARGV)
      case arguments.shift
      when "doctor"
        Doctor.new.run ? 0 : 1
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
            bonebed doctor
            bonebed baseline [--refresh]
            bonebed dig GEM [--phase require|install] [--require PATH] [--version VERSION] [--offline]
            bonebed dig --gemfile Gemfile.lock [--phase require|install]
            bonebed survey (--top N | --file FILE | --gemfile FILE) [--phase require|install]
            bonebed report RESULTS_DIR [--format md]
        HELP
        0
      else
        warn "Unknown command. Run `bonebed help` for usage."
        1
      end
    rescue OptionParser::ParseError, ArgumentError, Gem::LoadError => error
      warn error.message
      1
    end

    def self.dig(arguments)
      options = {phase: "require", results_dir: "results", timeout: 30, offline: false, gemfile: nil, require_path: nil}
      OptionParser.new do |parser|
        parser.on("--phase PHASE") { |value| options[:phase] = value }
        parser.on("--require PATH") { |value| options[:require_path] = value }
        parser.on("--version VERSION") { |value| options[:version] = value }
        parser.on("--results DIR") { |value| options[:results_dir] = value }
        parser.on("--timeout SECONDS", Integer) { |value| options[:timeout] = value }
        parser.on("--offline") { options[:offline] = true }
        parser.on("--gemfile FILE") { |value| options[:gemfile] = value }
      end.parse!(arguments)
      name = arguments.shift
      raise ArgumentError, "unexpected arguments: #{arguments.join(" ")}" unless arguments.empty?

      dig = Dig.new(**options.slice(:results_dir, :timeout, :offline))
      if options[:gemfile]
        raise ArgumentError, "GEM cannot be combined with --gemfile" if name
        raise ArgumentError, "--require cannot be combined with --gemfile" if options[:require_path]

        Survey.new(dig:).run(Survey.lockfile(options[:gemfile]), phase: options[:phase]) ? 0 : 1
      else
        puts dig.run(name, phase: options[:phase], version: options[:version], require_path: options[:require_path])
        dig.last_errors.empty? ? 0 : 1
      end
    end

    def self.survey(arguments)
      options = {phase: "install", results_dir: "results", timeout: 30, offline: false}
      OptionParser.new do |parser|
        parser.on("--top N", Integer) { |value| options[:top] = value }
        parser.on("--file FILE") { |value| options[:file] = value }
        parser.on("--gemfile FILE") { |value| options[:gemfile] = value }
        parser.on("--phase PHASE") { |value| options[:phase] = value }
        parser.on("--results DIR") { |value| options[:results_dir] = value }
        parser.on("--timeout SECONDS", Integer) { |value| options[:timeout] = value }
        parser.on("--offline") { options[:offline] = true }
      end.parse!(arguments)
      raise ArgumentError, "unexpected arguments: #{arguments.join(" ")}" unless arguments.empty?
      raise ArgumentError, "choose exactly one of --top, --file, or --gemfile" unless options.values_at(:top, :file, :gemfile).compact.one?
      raise ArgumentError, "phase must be require or install" unless Dig::PHASES.include?(options[:phase])

      entries = options[:top] ? Survey.top(options[:top]) : options[:file] ? Survey.file(options[:file]) : Survey.lockfile(options[:gemfile])
      dig = Dig.new(**options.slice(:results_dir, :timeout, :offline))
      Survey.new(dig:).run(entries, phase: options[:phase]) ? 0 : 1
    end

    def self.report(arguments)
      format = "md"
      OptionParser.new { |parser| parser.on("--format FORMAT") { |value| format = value } }.parse!(arguments)
      raise ArgumentError, "format must be md" unless format == "md"
      raise ArgumentError, "results directory is required" unless arguments.one?

      puts Report.new(arguments.first).markdown
      0
    end

    def self.baseline(arguments)
      refresh = false
      OptionParser.new { |parser| parser.on("--refresh") { refresh = true } }.parse!(arguments)
      raise ArgumentError, "unexpected arguments: #{arguments.join(" ")}" unless arguments.empty?

      puts Baseline.new.capture(refresh:).id
      0
    end
  end
end
