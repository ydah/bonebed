# frozen_string_literal: true

require "rbconfig"
require_relative "../session"

module Bonebed
  module Phase
    class Require
      def self.call(environment, specification, require_path: nil, **options)
        require_path ||= inferred_require_path(specification)
        raise Gem::LoadError, "#{specification.full_name} has no requirable entrypoint; use --require PATH" unless require_path

        code = 'gem ARGV[0], "=" + ARGV[1]; require ARGV[2]'
        collector = Session.new([RbConfig.ruby, "-e", code, specification.name, specification.version.to_s, require_path],
          env: environment.env, cwd: environment.project, unsetenv_others: true, **options).run
        [collector, require_path]
      end

      def self.inferred_require_path(specification)
        paths = [specification.name, specification.name.tr("-", "/")]
        paths.find do |path|
          specification.contains_requirable_file?(path)
        end || matching_top_level_file(specification)
      end

      def self.matching_top_level_file(specification)
        normalized_name = specification.name.delete("-_")
        paths = specification.full_require_paths.flat_map do |root|
          Dir[File.join(root, "*.{rb,#{RbConfig::CONFIG.fetch("DLEXT")}}")].map { |file| File.basename(file, ".*") }
        end.uniq
        paths.find { |path| path.delete("-_") == normalized_name } || (paths.first if paths.one?)
      end
    end
  end
end
