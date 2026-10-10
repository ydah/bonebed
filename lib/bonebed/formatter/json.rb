# frozen_string_literal: true

require "json"

module Bonebed
  module Formatter
    module JSON
      def self.call(manifests)
        ::JSON.pretty_generate(manifests)
      end
    end
  end
end
