# frozen_string_literal: true

require "cgi"
require_relative "tabular"

module Bonebed
  module Formatter
    module HTML
      def self.call(manifests, policy: nil)
        rows = Tabular.rows(Tabular.entries(manifests, policy:))
        table = rows.map { |row| "<tr>#{row.map { |value| "<td>#{CGI.escapeHTML(value.to_s)}</td>" }.join}</tr>" }.join("\n")
        headers = Tabular::HEADERS.map { |header| "<th scope=\"col\">#{header}</th>" }.join
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Bonebed findings</title><body><table><caption>Observed gem capabilities</caption><thead><tr>#{headers}</tr></thead><tbody>#{table}</tbody></table></body></html>"
      end
    end
  end
end
