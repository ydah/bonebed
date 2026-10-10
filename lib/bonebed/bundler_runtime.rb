# frozen_string_literal: true

require "bundler"
require "rbconfig"

module Bonebed
  module BundlerRuntime
    module_function

    def prepare(environment)
      specification = Gem.loaded_specs.fetch("bundler")
      raise Error, "Bundler runtime version does not match its specification" unless specification.version.to_s == Bundler::VERSION

      if !File.directory?(specification.full_gem_path) && (specification.default_gem? || stdlib_metadata_specification?(specification))
        source = Bundler.method(:root).source_location&.first
        expected = File.join(RbConfig::CONFIG.fetch("rubylibdir"), "bundler.rb")
        raise Error, "cannot verify default Bundler runtime source" unless source && File.file?(source) && File.file?(expected) && File.identical?(source, expected)
      else
        environment.copy_specification(specification)
      end
    end

    def stdlib_metadata_specification?(specification)
      return false unless specification.respond_to?(:source) && specification.source.instance_of?(Bundler::Source::Metadata)

      directory = File.join(RbConfig::CONFIG.fetch("rubylibdir"), "bundler", "source")
      origin = Bundler::Source::Metadata.instance_method(:specs).source_location&.first
      expected = File.join(directory, "metadata.rb")
      specification.loaded_from && File.directory?(specification.loaded_from) &&
        File.directory?(directory) && File.identical?(specification.loaded_from, directory) &&
        origin && File.file?(origin) && File.file?(expected) && File.identical?(origin, expected)
    end
    private_class_method :stdlib_metadata_specification?

    def command(*arguments)
      code = "gem 'bundler', '= #{Bundler::VERSION}'; require 'bundler'; " \
        "raise 'unexpected Bundler runtime version' unless Bundler::VERSION == #{Bundler::VERSION.inspect}; " \
        "require 'bundler/friendly_errors'; Bundler.with_friendly_errors { require 'bundler/cli'; Bundler::CLI.start(ARGV, debug: true) }"
      [RbConfig.ruby, "-e", code, "--", *arguments]
    end
  end
end
