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
        "- Require phase with IP sockets: #{network_count("require", %w[inet inet6])}",
        "- Require phase with Unix sockets: #{network_count("require", %w[unix])}",
        "- Install phase with IP sockets: #{network_count("install", %w[inet inet6])}",
        "- Install phase with Unix sockets: #{network_count("install", %w[unix])}",
        "",
        failures,
        ranking("Home files read", file_accesses("read", "$HOME/")),
        ranking("Project files read", file_accesses("read", "$PWD/")),
        ranking("Project files written", file_accesses("write", "$PWD/")),
        commands_by_target,
        openat_ranking
      ]
      lines.join("\n").rstrip << "\n"
    end

    private

    def network_count(phase, families)
      @manifests.count do |manifest|
        manifest["phase"] == phase && manifest.fetch("network", []).any? { |entry| families.include?(entry["family"]) }
      end
    end

    def failures
      failed = @manifests.reject { |manifest| manifest.fetch("errors", []).empty? }
      return "## Failures\n\nNone observed.\n" if failed.empty?

      rows = failed.map do |manifest|
        "| `#{label(manifest)}` | #{cell(manifest.fetch("errors").join("; "))} | #{cell(manifest.fetch("stdout", ""), limit: 500)} | #{cell(manifest.fetch("stderr", ""), limit: 500)} |"
      end
      details = failed.filter_map do |manifest|
        stdout = manifest.fetch("stdout", "")
        stderr = manifest.fetch("stderr", "")
        next if stdout.empty? && stderr.empty?

        <<~MARKDOWN
          ### `#{label(manifest)}`

          #### Stdout

          #{output_block(stdout)}

          #### Stderr

          #{output_block(stderr)}
        MARKDOWN
      end
      table = "## Failures\n\n| Survey target | Errors | Stdout | Stderr |\n| --- | --- | --- | --- |\n#{rows.join("\n")}\n"
      return table if details.empty?

      "#{table}\n<details>\n<summary>Full failure output</summary>\n\n#{details.join("\n")}\n</details>\n"
    end

    def file_accesses(mode, prefix)
      counts = Hash.new(0)
      @manifests.each do |manifest|
        manifest.dig("files", mode)&.each { |path| counts[path] += 1 if path.start_with?(prefix) }
      end
      counts
    end

    def commands_by_target
      counts = Hash.new(0)
      @manifests.each do |manifest|
        manifest.fetch("exec", []).each do |entry|
          counts[[label(manifest), entry.fetch("path")]] += entry.fetch("count", 1)
        end
      end
      rows = counts.map { |(target, command), count| [target, command, count] }
        .sort_by { |target, command, count| [target, -count, command] }
      return "## Commands observed by survey target\n\nNone observed.\n" if rows.empty?

      summary = rows.group_by(&:first).map do |target, entries|
        "| `#{target}` | #{entries.sum { |entry| entry.fetch(2) }} | #{entries.size} |"
      end.join("\n")
      details = rows.map { |target, command, count| "| `#{target}` | `#{command}` | #{count} |" }.join("\n")
      <<~MARKDOWN
        ## Commands observed by survey target

        | Survey target | Calls | Unique commands |
        | --- | ---: | ---: |
        #{summary}

        <details>
        <summary>All command paths</summary>

        | Survey target | Command | Count |
        | --- | --- | ---: |
        #{details}

        </details>
      MARKDOWN
    end

    # ponytail: keep Markdown compact; full stdout and stderr remain in the JSON manifest.
    def cell(value, limit: nil)
      text = value.to_s.gsub(/\s+/, " ").strip
      text = "—" if text.empty?
      text = "#{text[0, limit]}…" if limit && text.length > limit
      text.gsub("|", "\\|")
    end

    def output_block(value)
      value.lines(chomp: true).map { |line| "    #{line}" }.join("\n")
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
