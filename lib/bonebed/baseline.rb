# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "rbconfig"
require_relative "path_normalizer"
require_relative "session"

module Bonebed
  class Baseline
    Result = Struct.new(:id, :observation, keyword_init: true)

    def initialize(cache_dir: ".bonebed/baselines", timeout: 30)
      @cache_dir = cache_dir
      @timeout = timeout
    end

    def capture(refresh: false)
      return load unless refresh || !File.file?(path)

      collector = Session.new([RbConfig.ruby, "-e", ""], timeout: @timeout).run
      observation = collector.snapshot(PathNormalizer.new)
      raise Error, observation[:errors].join("; ") unless observation[:errors].empty?

      FileUtils.mkdir_p(@cache_dir)
      File.write(path, "#{JSON.pretty_generate(encode(observation))}\n")
      Result.new(id:, observation:)
    end

    private

    def id
      bundle = ENV["BUNDLE_GEMFILE"] ? "bundler" : "nobundler"
      gems = Gem.loaded_specs.values.map { |specification| "#{specification.name}-#{specification.version}" }.sort.join("\0")
      digest = Digest::SHA256.hexdigest(gems)[0, 8]
      "ruby-#{RUBY_VERSION}-#{bundle}-#{RbConfig::CONFIG.fetch("host_cpu")}-#{digest}"
    end

    def path
      File.join(@cache_dir, "#{id}.json")
    end

    def load
      Result.new(id:, observation: decode(JSON.parse(File.read(path))))
    end

    def encode(observation)
      observation.merge(
        network: entries(observation.fetch(:network)),
        exec: entries(observation.fetch(:exec))
      )
    end

    def entries(values)
      values.map { |event, count| {event:, count:} }
    end

    def decode(observation)
      {
        files: observation.fetch("files").to_h { |mode, values| [mode.to_sym, values] },
        network: decode_entries(observation.fetch("network")),
        exec: decode_entries(observation.fetch("exec")),
        stats: observation.fetch("stats").transform_keys(&:to_sym),
        errors: observation.fetch("errors")
      }
    end

    def decode_entries(entries)
      entries.to_h do |entry|
        [entry.fetch("event").transform_keys(&:to_sym), entry.fetch("count")]
      end
    end
  end
end
