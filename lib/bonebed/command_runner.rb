# frozen_string_literal: true

require "securerandom"
require "time"
require "digest"
require_relative "baseline"
require_relative "gem_environment"
require_relative "manifest_builder"
require_relative "result_store"
require_relative "enforcement"

module Bonebed
  class CommandRunner
    attr_reader :last_errors, :last_observer_errors

    def initialize(results_dir: "results", timeout: 60, offline: false, sinkhole: false, env_profile: "dev", writes_only: false,
      trace: nil, enforce: nil, deny: nil, quiet_target: false, output_limit: Session::OUTPUT_LIMIT, argv_limit: 64,
      cwd: nil, real_home: false, baseline: Baseline.new)
      raise ArgumentError, "sinkhole must be a boolean" unless [true, false].include?(sinkhole)
      raise ArgumentError, "offline and sinkhole cannot be combined" if offline && sinkhole
      raise ArgumentError, "trace is unsupported with sinkhole" if sinkhole && trace
      raise ArgumentError, "deny is incompatible with writes-only capture" if deny && writes_only
      raise ArgumentError, "timeout must be positive" unless timeout.is_a?(Numeric) && timeout.positive?
      raise ArgumentError, "invalid environment profile" unless %w[dev ci prod].include?(env_profile)
      raise ArgumentError, "output limit must be nonnegative" unless output_limit.is_a?(Integer) && output_limit >= 0
      raise ArgumentError, "argv limit must be positive" unless argv_limit.is_a?(Integer) && argv_limit.positive?

      @store = ResultStore.new(results_dir)
      @baseline = baseline
      @environment_options = {cwd:, real_home:}
      @env_profile = env_profile
      @enforce = enforce
      @deny = DenyPolicy.load(deny) if deny
      @session_options = {timeout:, offline:, sinkhole:, writes_only:, trace:, quiet_target:, output_limit:, argv_limit:, target_stdout: $stderr}
      @last_errors = []
      @last_observer_errors = []
    end

    def run(command)
      valid = command.is_a?(Array) && !command.empty? && command.all? { |argument| argument.is_a?(String) && !argument.include?("\0") }
      raise ArgumentError, "command must be a nonempty argv array without NUL bytes" unless valid && !command.first.empty?

      command = command.map(&:dup)
      command[0] = File.expand_path(command.first, @environment_options[:cwd] || Dir.pwd) if command.first.include?("/")
      @last_errors = []
      @last_observer_errors = []
      mode = @session_options.slice(:offline, :sinkhole, :writes_only).merge(env_profile: @env_profile)
      denial = @deny && DenyPolicy.context(@deny, name: "command", phase: "exec")
      baseline = @baseline.capture(phase: "require", enforce: @enforce, **mode, **(denial ? {deny: denial} : {}))
      GemEnvironment.open(**@environment_options) do |environment|
        environment.env.merge!({"CI" => "true", "GITHUB_ACTIONS" => "true", "GITHUB_REPOSITORY" => "example/app"}) if @env_profile == "ci"
        environment.env.merge!({"RAILS_ENV" => "production", "RACK_ENV" => "production"}) if @env_profile == "prod"
        options = @session_options.dup
        options[:deny] = DenyPolicy.in_environment(denial, environment) if denial
        options[:enforcement] = Enforcement.load(@enforce, environment) if @enforce
        run = {"id" => SecureRandom.uuid, "kind" => "command", "started_at" => Time.now.utc.iso8601,
               "mode" => mode.transform_keys(&:to_s).merge("honeypot" => true, "real_home" => @environment_options[:real_home],
                 "cwd" => @environment_options[:cwd] && File.expand_path(@environment_options[:cwd]),
                 "enforce" => @enforce && Digest::SHA256.file(@enforce).hexdigest,
                 "deny" => @deny && DenyPolicy.digest(@deny))}
        collector = Session.new(command, env: environment.env, cwd: environment.project, unsetenv_others: true, redactor: environment.honeypot, **options).run
        manifest = ManifestBuilder.call("command", "0", "exec", collector.snapshot(environment.normalizer), baseline, run:)
        manifest["command"] = command.map { |argument| environment.normalizer.scrub(argument) }
        manifest["run"]["command"] = manifest.fetch("command")
        manifest = environment.honeypot.redact(manifest)
        @last_errors = manifest.fetch("errors")
        @last_observer_errors = manifest.fetch("observer_errors")
        @store.write(manifest)
      end
    end
  end
end
