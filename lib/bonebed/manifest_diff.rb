# frozen_string_literal: true

require_relative "capability_keys"
require_relative "path_normalizer"

module Bonebed
  module ManifestDiff
    module_function

    def call(before, after, counts: false)
      previous = canonical_counts(before)
      current = canonical_counts(after)
      result = {"added" => (current.keys - previous.keys).sort, "removed" => (previous.keys - current.keys).sort}
      if counts
        result["counts"] = (previous.keys | current.keys).sort.each_with_object({}) do |key, changes|
          old_count = previous.fetch(key, 0)
          new_count = current.fetch(key, 0)
          changes[key] = {"before" => old_count, "after" => new_count} unless old_count == new_count
        end
      end
      result
    end

    def canonical_counts(manifest)
      identities = [manifest["gem"], *manifest.fetch("dependencies", [])].compact.map do |gem|
        suffix = (gem["platform"] && gem["platform"] != "ruby") ? "-#{gem.fetch("platform")}" : ""
        ["#{gem.fetch("name")}-#{gem.fetch("version")}#{suffix}", "#{gem.fetch("name")}-<version>#{suffix}"]
      end
      CapabilityKeys.counts(manifest).each_with_object(Hash.new(0)) do |(key, count), normalized|
        identities.each do |original, replacement|
          prefix = %r{(\$GEM_HOME/(?:gems/|specifications/|cache/|extensions/[^/]+/[^/]+/))#{Regexp.escape(original)}(?=/|:|\z|\.gem(?:spec)?(?:\z|:))}
          key = key.gsub(prefix) { "#{Regexp.last_match(1)}#{replacement}" }
        end
        key = key.gsub(%r{(\$TMPDIR/[^:]*?/)[0-9a-f]{64}\.gem(?=:|\z)}) { "#{Regexp.last_match(1)}<package>.gem" }
        key = key.gsub(%r{\$(?:GEM_HOME|TMPDIR)/[^:]+}) { |path| PathNormalizer.normalize_build_temporaries(path) }
        normalized[key] += count
      end
    end
  end
end
