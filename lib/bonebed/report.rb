# frozen_string_literal: true

require "json"

module Bonebed
  class Report
    def initialize(directory)
      raise ArgumentError, "results directory does not exist: #{directory}" unless Dir.exist?(directory)

      @manifests = Dir[File.join(directory, "*.json")].map { |path| JSON.parse(File.read(path)) }
    end

    def markdown
      successful = @manifests.count { |manifest| manifest.fetch("errors", []).empty? }
      lines = [
        "# Bonebed survey",
        "",
        "- Manifests: #{@manifests.size}",
        "- Successful: #{successful}",
        "- With errors: #{@manifests.size - successful}",
        "- Require phase with network: #{network_count("require")}",
        "- Install phase with network: #{network_count("install")}",
        "",
        ranking("Home files read", home_reads),
        ranking("Commands observed", commands),
        openat_ranking
      ]
      lines.join("\n").rstrip << "\n"
    end

    private

    def network_count(phase)
      @manifests.count { |manifest| manifest["phase"] == phase && !manifest.fetch("network", []).empty? }
    end

    def home_reads
      counts = Hash.new(0)
      @manifests.each { |manifest| manifest.dig("files", "read")&.grep(/\A\$HOME\//)&.each { |path| counts[path] += 1 } }
      counts
    end

    def commands
      @manifests.each_with_object(Hash.new(0)) do |manifest, counts|
        manifest.fetch("exec", []).each { |entry| counts[entry.fetch("path")] += entry.fetch("count", 1) }
      end
    end

    def ranking(title, counts)
      rows = counts.sort_by { |name, count| [-count, name] }.first(10)
      return "## #{title}\n\nNone observed.\n" if rows.empty?

      "## #{title}\n\n| Item | Count |\n| --- | ---: |\n#{rows.map { |name, count| "| `#{name}` | #{count} |" }.join("\n")}\n"
    end

    def openat_ranking
      rows = @manifests.sort_by { |manifest| -manifest.dig("stats", "openat_after_baseline").to_i }.first(10)
      ranking("Open calls after baseline", rows.to_h { |manifest| [label(manifest), manifest.dig("stats", "openat_after_baseline").to_i] })
    end

    def label(manifest)
      "#{manifest.dig("gem", "name")} #{manifest.dig("gem", "version")} (#{manifest["phase"]})"
    end
  end
end
