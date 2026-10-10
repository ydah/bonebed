# frozen_string_literal: true

require "bonebed"
require "bonebed/nightly_regression"
require "bonebed/nightly_artifacts"
require "tmpdir"

begin
  report = Dir.mktmpdir("bonebed-nightly-") do |directory|
    metadata = Bonebed::NightlyArtifacts.new(repository: ENV.fetch("GITHUB_REPOSITORY"), run_id: ENV.fetch("GITHUB_RUN_ID")).fetch(directory)
    if metadata["status"] == "error"
      {"schema_version" => 1, "fetch" => metadata}
    else
      observations = %w[current previous].map do |side|
        next {"manifests" => [], "errors" => []} if side == "previous" && metadata["status"] == "no_previous"
        Bonebed::NightlyRegression.read(File.join(directory, side, "nightly-observations"))
      end
      benchmarks = %w[current previous].map do |side|
        path = File.join(directory, side, "nightly-benchmark", "benchmark.json")
        next unless File.file?(path)
        raise ArgumentError, "benchmark exceeds size limit" if File.size(path) > Bonebed::NightlyRegression::MAX_BYTES
        JSON.parse(File.read(path), max_nesting: 32)
      end
      Bonebed::NightlyRegression.compare(current: observations.first.fetch("manifests"),
        previous: (metadata["status"] == "no_previous") ? nil : observations.last.fetch("manifests")).merge(
          "fetch" => metadata, "input_errors" => {"current" => observations.first.fetch("errors"), "previous" => observations.last.fetch("errors")},
          "benchmark" => Bonebed::NightlyRegression.benchmark(*benchmarks)
        )
    end
  end
  File.write(ARGV.fetch(0), JSON.pretty_generate(report) + "\n")
  exit 1 if report.dig("fetch", "status") == "error"
rescue => error
  File.write(ARGV.fetch(0), JSON.pretty_generate("schema_version" => 1, "fetch" => {"status" => "error", "error" => "#{error.class}: #{error.message}"}) + "\n")
  exit 1
end
