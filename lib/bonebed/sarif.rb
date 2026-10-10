# frozen_string_literal: true

require_relative "formatter/sarif"

module Bonebed
  module Sarif
    LEVELS = Formatter::SARIF::LEVELS
    SCORES = Formatter::SARIF::SCORES

    def self.call(manifests, **options)
      Formatter::SARIF.document(manifests, **options)
    end

    def self.validate_finding!(finding)
      Formatter::SARIF.validate_finding!(finding)
    end

    def self.artifact_uri(path, root)
      Formatter::SARIF.artifact_uri(path, root)
    end
  end
end
