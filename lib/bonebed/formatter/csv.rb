# frozen_string_literal: true

require_relative "tabular"

module Bonebed
  module Formatter
    module CSV
      def self.call(manifests, policy: nil)
        ([Tabular::HEADERS] + Tabular.rows(Tabular.entries(manifests, policy:))).map do |row|
          row.map do |value|
            text = value.to_s
            text = "'#{text}" if text.match?(/\A[=+\-@\t\r\n]/)
            "\"#{text.gsub('"', '""')}\""
          end.join(",")
        end.join("\r\n") << "\r\n"
      end
    end
  end
end
