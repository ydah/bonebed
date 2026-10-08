# frozen_string_literal: true

require "fileutils"
require_relative "version"

module Bonebed
  class DockerRunner
    def initialize(cwd: Dir.pwd, image: ENV.fetch("BONEBED_IMAGE", "ghcr.io/ydah/bonebed:#{VERSION}"))
      raise ArgumentError, "invalid container image" unless image.is_a?(String) && /\A[a-zA-Z0-9][a-zA-Z0-9._\/:@-]*\z/.match?(image)

      @cwd = File.realpath(cwd)
      @image = image
    end

    def run(arguments)
      invocation = command(arguments)
      FileUtils.mkdir_p(@results)
      system(*invocation)
      $?.exitstatus || 1
    end

    def command(arguments)
      raise ArgumentError, "usage: bonebed --docker COMMAND [OPTIONS]" if arguments.empty? || arguments.first == "--docker"

      forwarded = arguments.dup
      options = forwarded.take(forwarded.index("--") || forwarded.length)
      index = options.index("--results")
      equal_index = options.index { |value| value.start_with?("--results=") }
      results = if index
        raise ArgumentError, "--results requires a directory" unless options[index + 1]
        forwarded[index + 1]
      elsif equal_index
        forwarded[equal_index].delete_prefix("--results=")
      else
        "results"
      end
      @results = File.expand_path(results, @cwd)
      raise ArgumentError, "results must not replace the project mount" if @results == @cwd
      ancestor = @results
      loop do
        raise ArgumentError, "results path cannot contain symlinks" if File.symlink?(ancestor)
        break if ancestor == File.dirname(ancestor)
        ancestor = File.dirname(ancestor)
      end
      raise ArgumentError, "mount paths cannot contain commas" if [@cwd, @results].any? { |path| path.include?(",") }
      if index
        forwarded[index + 1] = "/results"
      elsif equal_index
        forwarded[equal_index] = "--results=/results"
      elsif %w[dig survey run bundle compare diff-lock history lock monitor].include?(forwarded.first)
        forwarded.insert(1, "--results", "/results")
      end
      output_option, default_path = case forwarded.first
      when "monitor" then ["--state", "/results/monitor.json"]
      when "lock" then ["--output", "/results/Gemfile.capabilities.lock"]
      when "dataset" then ["--output", "/results/site"]
      end
      if output_option && options.none? { |value| value == output_option || value.start_with?("#{output_option}=") }
        forwarded.insert(1, output_option, default_path)
      end
      profile = File.expand_path("../../contrib/docker-seccomp.json", __dir__)
      ["docker", "run", "--rm", "--init", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--security-opt", "seccomp=#{profile}",
        "--pids-limit", "512", "--memory", "2g", "--cpus", "2", "--user", "#{Process.uid}:#{Process.gid}",
        "--env", "HOME=/tmp", "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=1g,mode=1777",
        "--mount", "type=bind,source=#{@cwd},target=/work,readonly",
        "--mount", "type=bind,source=#{@results},target=/results", "--workdir", "/work",
        "--env", "BONEBED_BASELINE_DIR=/tmp/bonebed-baselines", "--env", "BONEBED_GEM_CACHE=/tmp/bonebed-gems", @image, *forwarded]
    end
  end
end
