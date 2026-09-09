# frozen_string_literal: true

require "bundler"
require "json"
require "net/http"
require "uri"

module Bonebed
  class Survey
    STATS_URL = "https://rubygems.org/stats"

    def initialize(dig:, output: $stdout)
      @dig = dig
      @output = output
    end

    def run(entries, phase:)
      entries.each_with_index do |entry, index|
        name, version = entry.values_at(:name, :version)
        if @dig.result_exists?(name, phase:, version:)
          @output.puts "[#{index + 1}/#{entries.size}] skip #{name}"
          next
        end

        @output.puts "[#{index + 1}/#{entries.size}] #{phase} #{name}"
        @dig.run(name, phase:, version:)
      rescue StandardError => error
        @output.puts "  failed: #{error.message}"
        write_failure(name, version, phase, error)
      end
    end

    def self.top(limit)
      raise ArgumentError, "top must be between 1 and 100" unless (1..100).cover?(limit)

      names = (1..(limit / 10.0).ceil).flat_map { |page| names_from(fetch_page(page)) }.uniq
      raise Error, "RubyGems stats returned only #{names.size} gem names" if names.size < limit

      names.first(limit).map { |name| {name:, version: nil} }
    end

    def self.file(path)
      File.readlines(path, chomp: true).filter_map do |line|
        name, version = line.sub(/#.*/, "").split
        {name:, version:} if name
      end
    end

    def self.lockfile(path)
      parser = Bundler::LockfileParser.new(Bundler.read_file(path))
      parser.specs.group_by(&:name).map do |name, specifications|
        {name:, version: specifications.max_by(&:version).version.to_s}
      end.sort_by { |entry| entry[:name] }
    end

    def self.names_from(html)
      html.scan(%r{href="/gems/([^"?]+)}).flatten.map { |name| URI::DEFAULT_PARSER.unescape(name) }
    end
    private_class_method :names_from

    def self.fetch_page(page)
      uri = URI("#{STATS_URL}?page=#{page}")
      Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 10, read_timeout: 10) do |http|
        response = http.get(uri.request_uri)
        raise Error, "RubyGems stats returned HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

        response.body
      end
    end
    private_class_method :fetch_page

    private

    def write_failure(name, version, phase, error)
      @dig.write_failure(name, phase:, version: version || "unknown", error:)
    rescue ArgumentError
      nil
    end
  end
end
