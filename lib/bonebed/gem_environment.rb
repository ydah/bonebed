# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require "rubygems/resolver"
require_relative "honeypot"
require_relative "path_normalizer"

module Bonebed
  class GemEnvironment
    attr_reader :root, :gem_home, :home, :project, :tmpdir, :prefetch, :env, :honeypot

    def self.open(**options)
      Dir.mktmpdir("bonebed-") do |root|
        yield new(root, **options)
      end
    end

    def initialize(root, real_home: false, cwd: nil, honeypot: true)
      @root = root
      @gem_home = File.join(root, "gems")
      @home = real_home ? Dir.home : File.join(root, "home")
      @project = cwd ? File.expand_path(cwd) : File.join(root, "project")
      @tmpdir = File.join(root, "tmp")
      @prefetch = File.join(root, "prefetch")
      raise ArgumentError, "working directory does not exist: #{cwd}" if cwd && !Dir.exist?(@project)

      FileUtils.mkdir_p([@gem_home, @home, @project, @tmpdir, @prefetch])
      @honeypot = Honeypot.new(home: real_home ? nil : @home, project: cwd ? nil : @project) if honeypot
      @env = {
        "PATH" => ENV.fetch("PATH", "/usr/local/bin:/usr/bin:/bin"), "LANG" => "C.UTF-8",
        "HOME" => @home, "TMPDIR" => @tmpdir,
        "GEM_HOME" => @gem_home, "GEM_PATH" => @gem_home
      }.merge(@honeypot&.env || {})
    end

    def normalizer
      PathNormalizer.new(home: @home, cwd: @project, tmpdir: @root,
        gem_paths: [@gem_home, File.join(@root, "bundler-observation", "plugin"), *Gem.path])
    end

    def copy_gems(specification)
      dependency = Gem::Dependency.new(specification.name, "=#{specification.version}")
      specifications = Gem::Resolver.for_current_gems([dependency]).resolve.map(&:spec).uniq(&:full_name)
      specifications.each { |resolved| copy_specification(resolved) }
      specifications
    end

    def copy_specification(specification)
      name = specification.full_name
      raise ArgumentError, "invalid gem directory name" unless File.basename(name) == name && !%w[. ..].include?(name)

      copy_tree(specification.full_gem_path, File.join(@gem_home, "gems", name))
      specifications = File.join(@gem_home, "specifications")
      FileUtils.mkdir_p(specifications)
      FileUtils.copy_file(specification.loaded_from, File.join(specifications, "#{name}.gemspec"))
      extension_dir = specification.extension_dir
      prefix = "#{specification.base_dir}/"
      return unless Dir.exist?(extension_dir) && extension_dir.start_with?(prefix)

      relative = extension_dir.delete_prefix(prefix)
      raise ArgumentError, "invalid extension directory" if relative.split("/").include?("..")

      copy_tree(extension_dir, File.join(@gem_home, relative))
    end

    private

    def copy_tree(source, destination, boundary: File.realpath(source), ancestors: [])
      path = File.realpath(source)
      raise ArgumentError, "gem symlink points outside its source tree: #{source}" unless path == boundary || path.start_with?("#{boundary}/")
      raise ArgumentError, "cyclic gem symlink: #{source}" if ancestors.include?(path)

      if File.directory?(path)
        FileUtils.mkdir_p(destination)
        Dir.each_child(path) do |name|
          copy_tree(File.join(path, name), File.join(destination, name), boundary:, ancestors: [*ancestors, path])
        end
      elsif File.file?(path)
        FileUtils.mkdir_p(File.dirname(destination))
        FileUtils.copy_file(path, destination, true)
      else
        raise ArgumentError, "unsupported gem file: #{source}"
      end
    end
  end
end
