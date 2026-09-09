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
      when nil, "help", "--help", "-h"
        puts <<~HELP
          Usage:
            bonebed doctor
            bonebed baseline [--refresh]
            bonebed dig GEM [--phase require|install] [--version VERSION] [--offline]
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
      options = {phase: "require", results_dir: "results", timeout: 30, offline: false}
      OptionParser.new do |parser|
        parser.on("--phase PHASE") { |value| options[:phase] = value }
        parser.on("--version VERSION") { |value| options[:version] = value }
        parser.on("--results DIR") { |value| options[:results_dir] = value }
        parser.on("--timeout SECONDS", Integer) { |value| options[:timeout] = value }
        parser.on("--offline") { options[:offline] = true }
      end.parse!(arguments)
      name = arguments.shift
      raise ArgumentError, "unexpected arguments: #{arguments.join(" ")}" unless arguments.empty?

      puts Dig.new(**options.slice(:results_dir, :timeout, :offline)).run(name, phase: options[:phase], version: options[:version])
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
