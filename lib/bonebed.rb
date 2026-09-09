# frozen_string_literal: true

require_relative "bonebed/version"

module Bonebed
  class Error < StandardError; end
end

require_relative "bonebed/doctor"
require_relative "bonebed/dig"
require_relative "bonebed/survey"
require_relative "bonebed/report"
