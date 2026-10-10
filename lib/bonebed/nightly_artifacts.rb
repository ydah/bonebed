# frozen_string_literal: true

require "json"
require "open3"
require "timeout"
require "time"
require "fileutils"

module Bonebed
  class NightlyArtifacts
    MAX_OUTPUT = 2 * 1024 * 1024
    MAX_ARTIFACT = 64 * 1024 * 1024
    NAMES = %w[nightly-observations nightly-benchmark].freeze

    def initialize(repository:, run_id:, timeout: 60)
      raise ArgumentError, "invalid repository" unless repository.match?(%r{\A[\w.-]+/[\w.-]+\z})
      raise ArgumentError, "invalid run id" unless run_id.to_s.match?(/\A[1-9]\d*\z/)
      @repository, @run_id, @timeout = repository, run_id.to_i, timeout
    end

    def fetch(directory)
      current = api("actions/runs/#{@run_id}")
      validate_run!(current)
      runs = api("actions/workflows/#{current.fetch("workflow_id")}/runs?status=success&per_page=100").fetch("workflow_runs")
      previous = runs.select do |run|
        run["id"] != @run_id && run["workflow_id"] == current["workflow_id"] && run["head_branch"] == current["head_branch"] &&
          run.dig("head_repository", "full_name") == @repository && run["conclusion"] == "success" &&
          Time.iso8601(run.fetch("created_at")) < Time.iso8601(current.fetch("created_at"))
      end.max_by { |run| run.fetch("created_at") }
      result = {"status" => previous ? "downloaded" : "no_previous", "current_run" => @run_id,
                "previous_run" => previous&.fetch("id"), "search_limit" => 100}
      download(current, File.join(directory, "current"))
      if previous
        result["previous_benchmark"] = download(previous, File.join(directory, "previous"), optional_benchmark: true).fetch("nightly-benchmark")
      end
      result
    rescue => error
      {"status" => "error", "current_run" => @run_id, "error" => "#{error.class}: #{error.message}"}
    end

    private

    def validate_run!(run)
      unless run["id"].is_a?(Integer) && run["workflow_id"].is_a?(Integer) &&
          run.dig("head_repository", "full_name") == @repository && run["head_branch"].is_a?(String) &&
          run["head_sha"].to_s.match?(/\A[0-9a-f]{40}\z/) && run["path"] == ".github/workflows/nightly.yml"
        raise ArgumentError, "unexpected workflow metadata"
      end
    end

    def download(run, directory, optional_benchmark: false)
      validate_run!(run)
      artifacts = api("actions/runs/#{run.fetch("id")}/artifacts?per_page=100").fetch("artifacts")
      NAMES.to_h do |name|
        matches = artifacts.select { |artifact| artifact["name"] == name }
        next [name, "no_previous_benchmark"] if optional_benchmark && name == "nightly-benchmark" && matches.empty?
        raise ArgumentError, "missing or ambiguous #{name}" unless matches.size == 1
        artifact = matches.first
        unless artifact["expired"] == false && artifact["size_in_bytes"].is_a?(Integer) && artifact["size_in_bytes"].between?(1, MAX_ARTIFACT) &&
            artifact.dig("workflow_run", "id") == run["id"] && artifact.dig("workflow_run", "head_sha") == run["head_sha"]
          raise ArgumentError, "invalid artifact metadata for #{name}"
        end
        destination = File.join(directory, name)
        FileUtils.mkdir_p(destination)
        gh("run", "download", run.fetch("id").to_s, "--repo", @repository, "--name", name, "--dir", destination)
        [name, "downloaded"]
      end
    end

    def api(path)
      JSON.parse(gh("api", "repos/#{@repository}/#{path}"), max_nesting: 32)
    end

    def gh(*arguments)
      output = +""
      Open3.popen2e("gh", *arguments, pgroup: true) do |input, stream, waiter|
        input.close
        begin
          Timeout.timeout(@timeout) do
            loop do
              output << stream.readpartial(16_384)
              raise IOError, "GitHub response exceeds size limit" if output.bytesize > MAX_OUTPUT
            rescue EOFError
              break
            end
            raise IOError, "GitHub command failed" unless waiter.value.success?
          end
          completed = true
        ensure
          begin
            Process.kill("KILL", -waiter.pid) unless completed
          rescue Errno::ESRCH
            nil
          end
        end
      end
      output
    end
  end
end
