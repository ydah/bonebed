# frozen_string_literal: true

require "tmpdir"

module Bonebed
  class PathNormalizer
    def initialize(home: Dir.home, gem_paths: Gem.path, tmpdir: Dir.tmpdir)
      @home = clean(home)
      @gem_paths = gem_paths.map { |path| clean(path) }.sort_by { |path| -path.length }
      @tmpdir = clean(tmpdir)
    end

    def call(path)
      gem_path = @gem_paths.find { |root| inside?(path, root) }
      return replace(path, gem_path, "$GEM_HOME") if gem_path
      return replace(path, @home, "$HOME") if inside?(path, @home)
      return path == @tmpdir ? "$TMPDIR" : "$TMPDIR/<random>" if inside?(path, @tmpdir)

      path.sub(%r{\A/proc/\d+(?=/|\z)}, "/proc/<pid>")
    end

    private

    def clean(path)
      path.to_s.sub(%r{/+\z}, "")
    end

    def inside?(path, root)
      !root.empty? && (path == root || path.start_with?("#{root}/"))
    end

    def replace(path, root, marker)
      "#{marker}#{path.delete_prefix(root)}"
    end
  end
end
