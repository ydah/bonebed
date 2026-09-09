# frozen_string_literal: true

require "bonebed"

module Bonebed
  class CLI
    def self.start(arguments = ARGV)
      case arguments.shift
      when "doctor"
        Doctor.new.run ? 0 : 1
      when nil, "help", "--help", "-h"
        puts "Usage: bonebed doctor"
        0
      else
        warn "Unknown command. Run `bonebed help` for usage."
        1
      end
    end
  end
end
