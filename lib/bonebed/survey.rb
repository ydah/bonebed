# frozen_string_literal: true

require "bundler"
require "json"
require "net/http"
require "uri"

module Bonebed
  class Survey
    attr_reader :last_observer_errors

    STATS_URL = "https://rubygems.org/stats"

    def initialize(dig:, output: $stdout, isolate: false, jobs: 1)
      raise ArgumentError, "jobs must be a positive integer" unless jobs.is_a?(Integer) && jobs.positive?

      @dig = dig
      @output = output
      @isolate = isolate
      @jobs = jobs
      @last_observer_errors = []
    end

    def run(entries, phase:)
      successful = true
      @last_observer_errors = []
      return run_workers(entries, phase:) if @isolate || @jobs > 1

      entries.each_with_index do |entry, index|
        name, version, require_path = entry.values_at(:name, :version, :require_path)
        require_path = nil if phase == "install"
        if @dig.result_exists?(name, phase:, version:, require_path:)
          @output.puts "[#{index + 1}/#{entries.size}] skip #{name}"
          next
        end

        @output.puts "[#{index + 1}/#{entries.size}] #{phase} #{name}"
        entry_successful, error, observer_errors = run_entry(name, version, phase, require_path)
        @last_observer_errors.concat(observer_errors || [])
        successful = false unless entry_successful
        @output.puts "  failed: #{error}" if error
      ensure
        GC.start unless @isolate
      end
      successful
    end

    def self.top(limit)
      raise ArgumentError, "top must be a positive integer" unless limit.is_a?(Integer) && limit.positive?

      names = []
      page = 1
      while names.size < limit
        additions = names_from(fetch_page(page)).uniq - names
        raise Error, "RubyGems stats returned only #{names.size} gem names" if additions.empty?

        names.concat(additions)
        page += 1
      end

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
      unsupported = parser.specs.reject { |spec| spec.source.is_a?(Bundler::Source::Rubygems) }.map(&:name)
      raise ArgumentError, "unsupported lockfile sources: #{unsupported.join(", ")}" unless unsupported.empty?

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

    def run_workers(entries, phase:)
      workers = {}
      pending = entries.each_with_index.filter_map do |entry, index|
        name, version, require_path = entry.values_at(:name, :version, :require_path)
        require_path = nil if phase == "install"
        if @dig.result_exists?(name, phase:, version:, require_path:)
          @output.puts "[#{index + 1}/#{entries.size}] skip #{name}"
          next
        end
        {name:, version:, require_path:, index:}
      end.uniq { |entry| entry.values_at(:name, :version, :require_path) }
      @dig.prepare_baselines(phase:) if @jobs > 1 && !pending.empty?
      successful = true
      until pending.empty? && workers.empty?
        while !pending.empty? && workers.size < @jobs
          entry = pending.shift
          @output.puts "[#{entry.fetch(:index) + 1}/#{entries.size}] #{phase} #{entry.fetch(:name)}"
          start_worker(workers, entry, phase)
        end
        IO.select(workers.keys).first.each do |reader|
          chunk = reader.read_nonblock(16_384, exception: false)
          next if chunk == :wait_readable

          if chunk
            workers.fetch(reader).fetch(:payload) << chunk
          else
            worker = workers.fetch(reader)
            reader.close
            entry_successful, error, observer_errors = worker_result(worker, phase)
            workers.delete(reader)
            successful = false unless entry_successful
            @last_observer_errors.concat(observer_errors || [])
            @output.puts "  failed: #{worker.fetch(:entry).fetch(:name)}: #{error}" if error
          end
        end
      end
      successful
    ensure
      stop_workers(workers) if workers
    end

    def start_worker(workers, entry, phase)
      reader, writer = IO.pipe
      Thread.handle_interrupt(Interrupt => :never) do
        pid = Process.fork do
          Signal.trap("INT", "DEFAULT")
          workers.each_key(&:close)
          reader.close
          begin
            Thread.handle_interrupt(Interrupt => :immediate) do
              writer.write(JSON.generate(run_entry(entry[:name], entry[:version], phase, entry[:require_path])))
            end
          rescue Interrupt
            exit! 130
          rescue Errno::EPIPE
            exit! 1
          ensure
            writer.close
          end
          exit! 0
        end
        writer.close
        workers[reader] = {pid:, entry:, payload: +"".b}
      end
    ensure
      writer&.close unless writer&.closed?
      reader&.close unless workers.key?(reader) || reader&.closed?
    end

    def worker_result(worker, phase)
      name, version = worker.fetch(:entry).values_at(:name, :version)
      _, status = Process.wait2(worker.fetch(:pid))
      unless status.success?
        message = status.signaled? ? "survey worker terminated by signal #{status.termsig}" : "survey worker exited with status #{status.exitstatus}"
        write_failure(name, version, phase, Error.new(message))
        return [false, message]
      end

      JSON.parse(worker.fetch(:payload))
    rescue => error
      write_failure(name, version, phase, error)
      [false, error.message]
    end

    def stop_workers(workers)
      workers.each_key { |reader| reader.close unless reader.closed? }
      pids = workers.values.map { |worker| worker.fetch(:pid) }
      pids.each { |pid| signal_worker(pid, "INT") }
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1
      until pids.empty? || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        pids.reject! do |pid|
          Process.waitpid(pid, Process::WNOHANG)
        rescue Errno::ECHILD
          true
        end
        sleep 0.01 unless pids.empty?
      end
      pids.each do |pid|
        signal_worker(pid, "KILL")
        begin
          Process.waitpid(pid)
        rescue Errno::ECHILD
          nil
        end
      end
    end

    def signal_worker(pid, signal)
      Process.kill(signal, pid)
    rescue Errno::ESRCH
      nil
    end

    def write_failure(name, version, phase, error)
      @dig.write_failure(name, phase:, version: version || "unknown", error:)
    rescue ArgumentError
      nil
    end
  end
end
