# frozen_string_literal: true

require "tmpdir"

module Bonebed
  class PathNormalizer
    def initialize(home: Dir.home, gem_paths: Gem.path, tmpdir: Dir.tmpdir, cwd: Dir.pwd)
      @home = clean(home)
      @gem_paths = gem_paths.map { |path| clean(path) }.sort_by { |path| -path.length }
      @tmpdir = clean(tmpdir)
      @cwd = clean(cwd)
    end

    def call(path)
      path = File.expand_path(path, @cwd) unless path.start_with?(File::SEPARATOR, "\0")
      gem_path = @gem_paths.find { |root| inside?(path, root) }
      return replace(path, gem_path, "$GEM_HOME") if gem_path
      return replace(path, @cwd, "$PWD") if inside?(path, @cwd)
      return replace(path, @home, "$HOME") if inside?(path, @home)
      if inside?(path, @tmpdir)
        return "$TMPDIR" if path == @tmpdir

        return path.sub(%r{\A#{Regexp.escape(@tmpdir)}/[^/]+}, "$TMPDIR/<random>")
      end

      path.sub(%r{\A/proc/(?:\d+|self|thread-self)/task/\d+(?=/|\z)}, "/proc/<pid>/task/<tid>")
        .sub(%r{\A/proc/\d+(?=/|\z)}, "/proc/<pid>")
    end

    def scrub(text)
      # Match complete absolute path tokens, including flag values and path lists.
      text.gsub(%r{(?<![\w/])/(?:[^\s"'=:;,]+)}) { |path| call(path) }
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
