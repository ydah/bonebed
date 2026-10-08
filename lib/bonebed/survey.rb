# frozen_string_literal: true

require "bundler"
require "json"
require "net/http"
require "uri"

module Bonebed
  class Survey
    attr_reader :last_observer_errors

    STATS_URL = "https://rubygems.org/stats"

    def initialize(dig:, output: $stdout, isolate: false)
      @dig = dig
      @output = output
      @isolate = isolate
      @last_observer_errors = []
    end

    def run(entries, phase:)
      successful = true
      @last_observer_errors = []
      entries.each_with_index do |entry, index|
        name, version, require_path = entry.values_at(:name, :version, :require_path)
        require_path = nil if phase == "install"
        if @dig.result_exists?(name, phase:, version:, require_path:)
          @output.puts "[#{index + 1}/#{entries.size}] skip #{name}"
          next
        end

        @output.puts "[#{index + 1}/#{entries.size}] #{phase} #{name}"
        entry_successful, error, observer_errors = @isolate ? isolated_run(name, version, phase, require_path) : run_entry(name, version, phase, require_path)
        @last_observer_errors.concat(observer_errors || [])
        successful = false unless entry_successful
        @output.puts "  failed: #{error}" if error
      ensure
        GC.start unless @isolate
      end
      successful
    end

    def self.top(limit)
      raise ArgumentError, "top must be between 1 and 100" unless (1..100).cover?(limit)

      names = (1..(limit / 10.0).ceil).flat_map { |page| names_from(fetch_page(page)) }.uniq
      raise Error, "RubyGems stats returned only #{names.size} gem names" if names.size < limit

      names.first(limit).map { |name| {name:, version: nil} }
    end

    def self.file(path)
      File.readlines(path, chomp: true).filter_map do |line|
        name, version, require_path = line.sub(/#.*/, "").split
        next unless name

        entry = {name:, version: (version == "-") ? nil : version}
        entry[:require_path] = require_path if require_path
        entry
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

    def run_entry(name, version, phase, require_path)
      @dig.run(name, phase:, version:, require_path:)
      [@dig.last_errors.empty?, nil, @dig.last_observer_errors]
    rescue Gem::LoadError, StandardError => error
      write_failure(name, version, phase, error)
      [false, error.message]
    end

    def isolated_run(name, version, phase, require_path)
      reader, writer = IO.pipe
      pid = Process.fork do
        reader.close
        Marshal.dump(run_entry(name, version, phase, require_path), writer)
        writer.close
        exit! 0
      end
      writer.close
      payload = reader.read
      _, status = Process.wait2(pid)
      unless status.success?
        message = status.signaled? ? "survey worker terminated by signal #{status.termsig}" : "survey worker exited with status #{status.exitstatus}"
        write_failure(name, version, phase, Error.new(message))
        return [false, message]
      end

      Marshal.load(payload)
    rescue => error
      write_failure(name, version, phase, error)
      [false, error.message]
    ensure
      [reader, writer].compact.each { |io| io.close unless io.closed? }
      begin
        Process.waitpid(pid) if pid
      rescue Errno::ECHILD
        nil
      end
    end

    def write_failure(name, version, phase, error)
      @dig.write_failure(name, phase:, version: version || "unknown", error:)
    rescue ArgumentError
      nil
    end
  end
end
