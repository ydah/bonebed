# frozen_string_literal: true

require "fileutils"
require "rubygems/package"
require "uri"
require "zlib"

module Bonebed
  module LocalGemRepository
    module_function

    # Generate the standard static RubyGems index without executing package contents or requiring
    # the optional rubygems-generate_index gem. Only explicitly supplied archives are available.
    def build(directory, packages)
      directory = File.expand_path(directory)
      FileUtils.mkdir_p(File.join(directory, "gems"))
      quick = File.join(directory, "quick", "Marshal.#{Gem.marshal_version}")
      FileUtils.mkdir_p(quick)
      specifications = packages.map do |path|
        package = Gem::Package.new(path)
        package.verify
        specification = package.spec
        raise ArgumentError, "invalid local package name" unless specification.full_name.match?(/\A[0-9A-Za-z][0-9A-Za-z._-]*\z/)

        destination = File.join(directory, "gems", "#{specification.full_name}.gem")
        FileUtils.copy_file(path, destination) unless File.expand_path(path) == destination
        File.binwrite(File.join(quick, "#{specification.full_name}.gemspec.rz"), Zlib::Deflate.deflate(Marshal.dump(specification)))
        specification
      end
      prerelease, released = specifications.uniq(&:full_name).partition { |spec| spec.version.prerelease? }
      {"specs" => released, "latest_specs" => released, "prerelease_specs" => prerelease}.each do |name, specs|
        contents = Marshal.dump(specs.map { |spec| [spec.name, spec.version, spec.platform.to_s] }.sort)
        path = File.join(directory, "#{name}.#{Gem.marshal_version}")
        File.binwrite(path, contents)
        Zlib::GzipWriter.open("#{path}.gz") { |file| file.write(contents) }
      end
      URI::File.build(path: URI::DEFAULT_PARSER.escape(directory)).to_s
    end
  end
end
