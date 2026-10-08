# frozen_string_literal: true

require "rbconfig"
require_relative "../session"

module Bonebed
  module Phase
    class Require
      def self.call(environment, specification, require_path: nil, **options)
        require_path ||= isolated_require_path(environment, specification)
        raise Gem::LoadError, "#{specification.full_name} has no requirable entrypoint; use --require PATH" unless require_path

        code = 'gem ARGV[0], "=" + ARGV[1]; require ARGV[2]'
        collector = Session.new([RbConfig.ruby, "-e", code, specification.name, specification.version.to_s, require_path],
          env: environment.env, cwd: environment.project, unsetenv_others: true, **options).run
        [collector, require_path]
      end

      def self.isolated_require_path(environment, specification)
        root = File.join(environment.gem_home, "gems", specification.full_name)
        roots = specification.require_paths.map { |path| File.expand_path(path, root) }
        roots.select! { |path| path.start_with?("#{root}/") || path == root }
        candidates = [specification.name, specification.name.tr("-", "/")]
        candidates.find { |name| roots.any? { |path| %w[rb so bundle].any? { |ext| File.file?(File.join(path, "#{name}.#{ext}")) } } } || begin
          files = roots.flat_map { |path| Dir[File.join(path, "*.{rb,so,bundle}")] }.map { |path| File.basename(path, ".*") }.uniq
          files.find { |name| name.delete("-_") == specification.name.delete("-_") } || (files.first if files.one?)
        end
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
