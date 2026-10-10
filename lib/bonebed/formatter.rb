# frozen_string_literal: true

require_relative "formatter/markdown"
require_relative "formatter/json"
require_relative "formatter/sarif"
require_relative "formatter/csv"
require_relative "formatter/html"

module Bonebed
  module Formatter
    FORMATS = {"md" => Markdown, "json" => JSON, "sarif" => SARIF, "csv" => CSV, "html" => HTML}.freeze

    def self.call(manifests, format, policy: nil, lockfile: nil)
      formatter = FORMATS.fetch(format) { raise ArgumentError, "format must be md, json, csv, html, or sarif" }
      return formatter.call(manifests, policy:, lockfile:) if format == "sarif"
      return formatter.call(manifests) if format == "json"

      formatter.call(manifests, policy:)
    end
  end
end
