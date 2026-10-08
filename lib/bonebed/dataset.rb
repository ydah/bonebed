# frozen_string_literal: true

require "cgi"
require "digest"
require "fileutils"
require "json"
require "tempfile"
require_relative "result_store"
require_relative "manifest_diff"

module Bonebed
  class Dataset
    REPOSITORY = "https://github.com/ydah/bonebed"

    def initialize(directory)
      raise ArgumentError, "results directory does not exist: #{directory}" unless Dir.exist?(directory)

      @manifests = ResultStore.read(directory)
      @manifests.each { |manifest| CapabilityKeys.call(manifest) }
    end

    def write(directory)
      directory = File.expand_path(directory)
      [directory, File.join(directory, "gems"), File.join(directory, "badges")].each do |path|
        raise ArgumentError, "dataset output cannot be a symlink: #{path}" if File.symlink?(path)

        FileUtils.mkdir_p(path)
      end
      gems = @manifests.group_by { |manifest| manifest.fetch("gem").fetch("name") }.sort.to_h
      index = gems.map do |name, observations|
        raise ArgumentError, "invalid dataset gem name" unless ResultStore::COMPONENT.match?(name)

        write_file(directory, "gems/#{name}.html", gem_page(name, observations))
        write_json(directory, "badges/#{name}.json", badge(observations))
        {"name" => name, "versions" => observations.map { |manifest| manifest.dig("gem", "version") }.uniq.sort,
         "phases" => observations.map { |manifest| manifest.fetch("phase") }.uniq.sort, "path" => "gems/#{name}.html"}
      end
      changes = version_changes
      write_file(directory, "index.html", index_page(index))
      write_json(directory, "search-index.json", index)
      write_json(directory, "manifests.json", @manifests)
      write_json(directory, "changes.json", changes)
      write_file(directory, "changes.rss", rss(changes))
      directory
    end

    def augment_sbom(sbom)
      unless sbom.is_a?(Hash) && sbom["bomFormat"] == "CycloneDX" && sbom["components"].is_a?(Array)
        raise ArgumentError, "expected a CycloneDX JSON object with components"
      end

      result = JSON.parse(JSON.generate(sbom))
      observations = @manifests.group_by { |manifest| manifest.fetch("gem").values_at("name", "version") }
      result.fetch("components").each do |component|
        raise ArgumentError, "invalid CycloneDX component" unless component.is_a?(Hash)
        raise ArgumentError, "invalid CycloneDX package URL" if component.key?("purl") && !component["purl"].is_a?(String)
        next if component["purl"] && !component["purl"].start_with?("pkg:gem/")

        manifests = observations[component.values_at("name", "version")]
        next unless manifests

        properties = component.fetch("properties", [])
        unless properties.is_a?(Array) && properties.all? { |entry| entry.is_a?(Hash) && entry["name"].is_a?(String) && entry["value"].is_a?(String) }
          raise ArgumentError, "invalid CycloneDX properties"
        end
        keys = manifests.flat_map { |manifest| CapabilityKeys.call(manifest) }.uniq.sort
        component["properties"] = properties.reject { |entry| entry["name"] == "bonebed:capabilities" } +
          [{"name" => "bonebed:capabilities", "value" => JSON.generate(keys)}]
      end
      result
    end

    private

    def version_changes
      @manifests.group_by do |manifest|
        [manifest.fetch("gem").fetch("name"), manifest["phase"], *manifest.fetch("gem").values_at("platform", "require_path"),
          ResultStore.mode_identity(manifest.dig("run", "mode")), manifest.dig("run", "executable"), manifest.dig("run", "arguments")]
      end.flat_map do |(name, phase, platform, require_path, mode, executable, arguments), manifests|
        manifests.select { |manifest| Gem::Version.correct?(manifest.dig("gem", "version")) }
          .group_by { |manifest| manifest.dig("gem", "version") }
          .sort_by { |version, _| Gem::Version.new(version) }.each_cons(2).filter_map do |(before_version, before), (after_version, after)|
          before_keys = before.flat_map { |manifest| ManifestDiff.canonical_counts(manifest).keys }.uniq
          after_keys = after.flat_map { |manifest| ManifestDiff.canonical_counts(manifest).keys }.uniq
          difference = {"added" => (after_keys - before_keys).sort, "removed" => (before_keys - after_keys).sort}
          next if difference.values.all?(&:empty?)

          {"name" => name, "phase" => phase, "platform" => platform, "require_path" => require_path, "mode" => ResultStore::MODE_KEYS.zip(mode).to_h,
           "executable" => executable, "arguments" => arguments,
           "from" => before_version, "to" => after_version,
           "started_at" => after.filter_map { |manifest| manifest.dig("run", "started_at") || manifest["started_at"] }.max}.merge(difference)
        end
      end
    end

    def badge(observations)
      versions = observations.filter_map do |manifest|
        version = manifest.dig("gem", "version")
        Gem::Version.new(version) if Gem::Version.correct?(version)
      end
      latest = versions.max
      observations = observations.select { |manifest| Gem::Version.correct?(manifest.dig("gem", "version")) && Gem::Version.new(manifest.dig("gem", "version")) == latest } if latest
      observed = observations.any? { |manifest| CapabilityKeys.call(manifest).any? { |key| key.start_with?("network:") } }
      incomplete = observations.any? do |manifest|
        !manifest.fetch("errors").empty? || !Array(manifest["observer_errors"]).empty? ||
          manifest.dig("target", "timed_out") || manifest.dig("target", "signal") ||
          ![nil, 0].include?(manifest.dig("target", "exit_status"))
      end
      message = if observed
        "observed"
      elsif incomplete || !latest
        "unknown"
      else
        "not observed"
      end
      {"schemaVersion" => 1, "label" => "network activity", "message" => message, "color" => "blue"}
    end

    def index_page(index)
      entries = index.map do |gem|
        "<li data-name=\"#{escape(gem.fetch("name"))}\"><a href=\"#{escape(gem.fetch("path"))}\">#{escape(gem.fetch("name"))}</a> — #{escape(gem.fetch("versions").join(", "))}</li>"
      end.join("\n")
      page("Gem observations", <<~HTML)
        <p>Recorded activity is an observation, not a safety verdict.</p>
        <p><a href="changes.rss">RSS changes</a> · <a href="changes.json">JSON changes</a> · <a href="manifests.json">Observation data</a></p>
        <label for="search">Find a gem</label> <input id="search" type="search" autocomplete="off">
        <ul>#{entries}</ul>
        <script>
          document.getElementById('search').addEventListener('input', function () {
            const query = this.value.toLowerCase();
            document.querySelectorAll('[data-name]').forEach(function (entry) {
              entry.hidden = !entry.dataset.name.toLowerCase().includes(query);
            });
          });
        </script>
      HTML
    end

    def gem_page(name, observations)
      entries = observations.map do |manifest|
        metadata = manifest.slice("tool", "run", "environment", "target", "errors", "observer_errors")
        identity = manifest.fetch("gem").values_at("version", "platform", "require_path").compact.join(" · ")
        keys = CapabilityKeys.call(manifest).map { |key| "<li><code>#{escape(key)}</code></li>" }.join("\n")
        "<section><h2>#{escape(identity)} — #{escape(manifest.fetch("phase"))}</h2><ul>#{keys}</ul>" \
          "<details><summary>Reproduction metadata</summary><pre>#{escape(JSON.pretty_generate(metadata))}</pre></details></section>"
      end.join("\n")
      page("#{name} observations", "<p><a href=\"../index.html\">All gems</a></p><p>Observed capabilities describe one execution; they do not establish safety or malicious intent.</p>#{entries}")
    end

    def page(title, body)
      <<~HTML
        <!doctype html>
        <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>#{escape(title)} · Bonebed</title>
        <style>body{font:1rem/1.6 system-ui,sans-serif;max-width:70rem;margin:2rem auto;padding:0 1rem;color:#17202a}a{color:#175b94}pre{overflow:auto;background:#f3f5f7;padding:1rem}code{overflow-wrap:anywhere}section{margin:2rem 0}input{font:inherit;padding:.3rem}</style>
        </head><body><main><h1>#{escape(title)}</h1>#{body}</main>
        <footer><p><a href="#{REPOSITORY}/issues/new?template=false_positive.yml">Request a correction</a> · <a href="#{REPOSITORY}/blob/main/SECURITY.md">Report a security issue privately</a></p></footer></body></html>
      HTML
    end

    def rss(changes)
      items = changes.map do |change|
        title = "#{change.fetch("name")} #{change.fetch("from")} → #{change.fetch("to")} (#{change.fetch("phase")})"
        description = "Added: #{change.fetch("added").join(", ")}. Removed: #{change.fetch("removed").join(", ")}. Observed changes are not a maliciousness verdict."
        "<item><title>#{xml(title)}</title><description>#{xml(description)}</description><guid isPermaLink=\"false\">#{Digest::SHA256.hexdigest(JSON.generate(change))}</guid></item>"
      end.join("\n")
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<rss version=\"2.0\"><channel><title>Bonebed observation changes</title><link>#{REPOSITORY}</link><description>Observed gem capability changes</description>#{items}</channel></rss>\n"
    end

    def escape(value)
      CGI.escapeHTML(value.to_s)
    end

    def xml(value)
      escape(value.to_s.gsub(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/, ""))
    end

    def write_json(directory, relative, value)
      write_file(directory, relative, JSON.pretty_generate(value) << "\n")
    end

    def write_file(directory, relative, content)
      path = File.join(directory, relative)
      raise ArgumentError, "dataset output cannot be a symlink: #{path}" if File.symlink?(path)

      Tempfile.create([".dataset-", ".tmp"], File.dirname(path)) do |file|
        file.write(content)
        file.flush
        File.rename(file.path, path)
      end
    end
  end
end
