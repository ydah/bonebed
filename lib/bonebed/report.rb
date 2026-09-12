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
        failures,
        ranking("Home files read", home_reads),
        commands_by_gem,
        openat_ranking
      ]
      lines.join("\n").rstrip << "\n"
    end

    private

    def network_count(phase)
      @manifests.count { |manifest| manifest["phase"] == phase && !manifest.fetch("network", []).empty? }
    end

    def failures
      rows = @manifests.filter_map do |manifest|
        errors = manifest.fetch("errors", [])
        unless errors.empty?
          "| `#{label(manifest)}` | #{cell(errors.join("; "))} | #{cell(manifest.fetch("stderr", ""), limit: 500)} |"
        end
      end
      return "## Failures\n\nNone observed.\n" if rows.empty?

      "## Failures\n\n| Gem | Errors | Stderr |\n| --- | --- | --- |\n#{rows.join("\n")}\n"
    end

    def home_reads
      counts = Hash.new(0)
      @manifests.each { |manifest| manifest.dig("files", "read")&.grep(/\A\$HOME\//)&.each { |path| counts[path] += 1 } }
      counts
    end

    def commands_by_gem
      counts = Hash.new(0)
      @manifests.each do |manifest|
        manifest.fetch("exec", []).each do |entry|
          counts[[label(manifest), entry.fetch("path")]] += entry.fetch("count", 1)
        end
      end
      rows = counts.map { |(gem, command), count| [gem, command, count] }
        .sort_by { |gem, command, count| [-count, gem, command] }.first(20)
      return "## Commands observed by gem\n\nNone observed.\n" if rows.empty?

      body = rows.map { |gem, command, count| "| `#{gem}` | `#{command}` | #{count} |" }.join("\n")
      "## Commands observed by gem\n\n| Gem | Command | Count |\n| --- | --- | ---: |\n#{body}\n"
    end

    # ponytail: keep Markdown compact; full stderr remains in the JSON manifest.
    def cell(value, limit: nil)
      text = value.to_s.gsub(/\s+/, " ").strip
      text = "—" if text.empty?
      text = "#{text[0, limit]}…" if limit && text.length > limit
      text.gsub("|", "\\|")
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
