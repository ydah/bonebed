# frozen_string_literal: true

require "digest"
require "fileutils"
require "tmpdir"
require "rubygems/package"
require "rubygems/request_set"
require "rubygems/remote_fetcher"

module Bonebed
  class Prefetcher
    class Error < Bonebed::Error; end

    PLATFORM_LOCK = Mutex.new
    private_constant :PLATFORM_LOCK

    def initialize(directory: ENV.fetch("BONEBED_GEM_CACHE", File.join(".bonebed", "gems")))
      @directory = File.expand_path(directory)
    end

    def call(name, version = nil, platform: nil)
      FileUtils.mkdir_p(@directory)
      # RubyGems resolves against a process-global platform list.
      PLATFORM_LOCK.synchronize do
        original_platforms = Gem.platforms
        begin
          Gem.platforms = [Gem::Platform::RUBY, Gem::Platform.new(platform)].uniq if platform
          requirement = version ? Gem::Requirement.new("= #{version}") : Gem::Requirement.default
          set = Gem::RequestSet.new(Gem::Dependency.new(name, requirement))
          set.resolve
          set.sorted_requests.map { |request| fetch(request.spec) }
        ensure
          Gem.platforms = original_platforms
        end
      end
    rescue => error
      raise Error, "prefetch_failed: #{error.class}: #{error.message}"
    end

    private

    def fetch(resolved)
      spec = resolved.spec
      key = Digest::SHA256.hexdigest([resolved.source.uri.to_s, spec.full_name].join("\0"))
      index = File.join(@directory, "#{key}.sha256")
      if File.file?(index)
        digest = File.read(index).strip
        if digest.match?(/\A[0-9a-f]{64}\z/)
          cached = File.join(@directory, "#{digest}.gem")
          return cached if File.file?(cached) && Digest::SHA256.file(cached).hexdigest == digest
        end
      end

      Dir.mktmpdir("fetch-", @directory) do |temporary|
        downloaded = resolved.download(install_dir: temporary)
        package = Gem::Package.new(downloaded)
        package.verify
        raise Error, "downloaded gem identity does not match #{spec.full_name}" unless package.spec.full_name == spec.full_name

        digest = Digest::SHA256.file(downloaded).hexdigest
        cached = File.join(@directory, "#{digest}.gem")
        File.rename(downloaded, cached)
        temporary_index = File.join(temporary, "digest")
        File.write(temporary_index, "#{digest}\n")
        File.rename(temporary_index, index)
        cached
      end
    end
  end
end
