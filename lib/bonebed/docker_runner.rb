# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "version"

module Bonebed
  class DockerRunner
    def initialize(cwd: Dir.pwd, image: ENV.fetch("BONEBED_IMAGE", "ghcr.io/ydah/bonebed:#{VERSION}"),
      ruby_image: ENV.fetch("BONEBED_RUBY_IMAGE", "ghcr.io/ydah/bonebed:#{VERSION}-ruby%{ruby}"))
      raise ArgumentError, "invalid container image" unless image.is_a?(String) && /\A[a-zA-Z0-9][a-zA-Z0-9._\/:@-]*\z/.match?(image)

      @cwd = File.realpath(cwd)
      @image = image
      @ruby_image = ruby_image
    end

    def run(arguments)
      options = arguments.take(arguments.index("--") || arguments.length)
      return run_rubies(arguments, options) if options.any? { |arg| arg == "--ruby" || arg.start_with?("--ruby=") }

      invocation = command(arguments)
      FileUtils.mkdir_p(@results)
      execute(invocation)
    end

    def execute(invocation)
      system(*invocation)
      $?.exitstatus || 1
    end

    def command(arguments)
      raise ArgumentError, "usage: bonebed --docker COMMAND [OPTIONS]" if arguments.empty? || arguments.first == "--docker"

      forwarded = arguments.dup
      options = forwarded.take(forwarded.index("--") || forwarded.length)
      raise ArgumentError, "specify --results only once" if options.count { |arg| arg == "--results" || arg.start_with?("--results=") } > 1
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
      if @results == @cwd || @cwd.start_with?(@results.delete_suffix("/") + "/")
        raise ArgumentError, "results must not include the project mount"
      end
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

    private

    def run_rubies(arguments, options)
      raise ArgumentError, "--ruby supports dig, survey, run and bundle" unless %w[dig survey run bundle].include?(arguments.first)
      raise ArgumentError, "request command help without --ruby" if options.any? { |arg| %w[-h --help].include?(arg) }
      indexes = options.each_index.select { |index| options[index] == "--ruby" || options[index].start_with?("--ruby=") }
      raise ArgumentError, "specify --ruby only once" unless indexes.one?
      index = indexes.first
      forwarded = arguments.dup
      value = forwarded.delete_at(index)
      versions = ((value == "--ruby") ? forwarded.delete_at(index) : value.delete_prefix("--ruby=")).to_s.split(",", -1)
      unless versions.size.between?(1, 8) && versions.uniq == versions && versions.all? { |version| /\A(?:3\.[2-9]|[4-9]\.[0-9])\z/.match?(version) }
        raise ArgumentError, "--ruby requires 1 to 8 distinct Ruby major.minor versions (3.2 or newer)"
      end
      raise ArgumentError, "Ruby image template requires exactly one %{ruby} placeholder" unless @ruby_image.is_a?(String) && @ruby_image.scan("%{ruby}").size == 1
      runners = versions.map { |version| self.class.new(cwd: @cwd, image: @ruby_image.sub("%{ruby}", version)) }
      command(forwarded)
      FileUtils.mkdir_p(@results)
      root = Dir.mktmpdir("ruby-matrix-", @results)
      option_count = forwarded.index("--") || forwarded.length
      result_index = forwarded.take(option_count).index { |arg| arg == "--results" || arg.start_with?("--results=") }
      if result_index
        flag = forwarded.delete_at(result_index)
        forwarded.delete_at(result_index) if flag == "--results"
      end
      statuses = versions.zip(runners).to_h do |version, runner|
        invocation = runner.command([forwarded.first, "--results", File.join(root, "ruby-#{version}"), *forwarded.drop(1)])
        FileUtils.mkdir_p(File.join(root, "ruby-#{version}"))
        [version, execute(invocation)]
      end
      require_relative "result_store"
      require_relative "manifest_diff"
      observations = versions.to_h { |version| [version, ResultStore.read(File.join(root, "ruby-#{version}"))] }
      observations.each do |version, manifests|
        if manifests.empty? && statuses[version].zero?
          warn "Ruby #{version} produced no observations"
          statuses[version] = 2
        end
        next if manifests.all? { |manifest| manifest.dig("environment", "ruby").to_s.start_with?("#{version}.") }

        warn "Ruby image mismatch for #{version}; excluding its observations"
        statuses[version] = 2
        observations[version] = []
      end
      comparisons = versions.each_cons(2).flat_map do |before, after|
        previous = matrix_observations(observations.fetch(before))
        current = matrix_observations(observations.fetch(after))
        (previous.keys | current.keys).map do |identity|
          left, right = previous[identity], current[identity]
          {ruby_before: before, ruby_after: after, identity:,
           observed_before: !left.nil?, observed_after: !right.nil?,
           difference: ({added: (right - left).sort, removed: (left - right).sort} if left && right)}
        end
      end
      puts JSON.pretty_generate(results: root, statuses:, comparisons:)
      statuses.values.find { |status| ![0, 1].include?(status) } || (statuses.value?(1) ? 1 : 0)
    end

    def matrix_observations(manifests)
      complete = manifests.select do |manifest|
        manifest["errors"] == [] && manifest["observer_errors"] == [] &&
          manifest.dig("target", "exit_status") == 0 && !manifest.dig("target", "signal") && !manifest.dig("target", "timed_out")
      end
      groups = complete.group_by do |manifest|
        [manifest["phase"], manifest.fetch("gem").values_at("name", "version", "platform", "require_path"),
          manifest["command"], manifest.dig("run", "executable"), manifest.dig("run", "arguments")]
      end
      groups.transform_values do |samples|
        samples = samples.group_by { |sample| sample.dig("run", "repeat", "group") }.flat_map do |group, repeated|
          next repeated unless group
          count = repeated.first.dig("run", "repeat", "count")
          valid = count.is_a?(Integer) && count.between?(1, 100) &&
            repeated.map { |sample| sample.dig("run", "repeat", "index") }.sort == (1..count).to_a &&
            repeated.all? { |sample| sample.dig("run", "repeat", "count") == count && sample.dig("stability", "complete") == true }
          valid ? repeated : []
        end
        next if samples.empty?
        # Compare unions across repetitions; counts are intentionally not compared across runtimes.
        samples.flat_map { |sample| ManifestDiff.canonical_counts(sample).keys }.uniq
      end.compact
    end
  end
end
