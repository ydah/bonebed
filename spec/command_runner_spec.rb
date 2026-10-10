# frozen_string_literal: true

require "bonebed/command_runner"
require "bonebed/cli"
require "tmpdir"

RSpec.describe Bonebed::CommandRunner do
  around do |example|
    Dir.mktmpdir("bonebed-run-") do |root|
      @root = root
      example.run
    end
  end

  let(:baseline) do
    normalizer = Bonebed::PathNormalizer.new
    double(capture: Bonebed::Baseline::Result.new(id: "test", observation: Bonebed::Collector.new.snapshot(normalizer)))
  end
  let(:runner) { described_class.new(results_dir: File.join(@root, "results"), baseline:, quiet_target: true) }

  it "requires a nonempty argv array without NUL bytes" do
    [nil, [], "echo hello", [""], ["echo", "bad\0argument"], ["echo", 1]].each do |command|
      expect { runner.run(command) }.to raise_error(ArgumentError)
    end
  end

  it "observes literal arguments in a disposable directory with a clean environment" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")

    original = ENV["BONEBED_TEST_SECRET"]
    ENV["BONEBED_TEST_SECRET"] = "host-secret-must-not-be-inherited"
    code = 'puts ARGV.first; puts ENV.fetch("BONEBED_TEST_SECRET", "missing"); puts ENV.fetch("HOME"); File.write("created", "ok")'
    argument = "literal;$(echo shell-expanded)"
    path = runner.run([RbConfig.ruby, "-e", code, argument])
    result = JSON.parse(File.read(path))
    expect(result["phase"]).to eq("exec")
    expect(result.dig("run", "kind")).to eq("command")
    expect(result["command"].last).to eq(argument)
    expect(result["stdout"]).to include(argument, "missing")
    expect(result["stdout"]).not_to include("host-secret-must-not-be-inherited")
    expect(result.dig("files", "write")).to include("$PWD/created")
    expect(result.dig("target", "exit_status")).to eq(0)
    expect(runner.last_errors).to be_empty
  ensure
    original ? ENV["BONEBED_TEST_SECRET"] = original : ENV.delete("BONEBED_TEST_SECRET")
  end

  it "does not interpret a single command string through a shell" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")

    marker = File.join(@root, "shell-executed")
    path = runner.run(["touch #{marker}"])
    expect(File).not_to exist(marker)
    expect(JSON.parse(File.read(path))["errors"]).not_to be_empty
  end

  it "captures target failure, environment profile, and trace output" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")

    trace = File.join(@root, "command.jsonl")
    runner = described_class.new(results_dir: File.join(@root, "results"), baseline:, quiet_target: true, env_profile: "ci", trace:)
    path = runner.run([RbConfig.ruby, "-e", 'puts ENV.fetch("CI"); exit 7'])
    result = JSON.parse(File.read(path))
    expect(result.dig("target", "exit_status")).to eq(7)
    expect(result["stdout"]).to include("true")
    expect(result.dig("run", "mode", "env_profile")).to eq("ci")
    expect(runner.last_errors).not_to be_empty
    expect(File.readlines(trace)).not_to be_empty
  end

  it "forwards enforcement and observation limits with environment clearing" do
    collector = Bonebed::Collector.new
    collector.finish(Process.clock_gettime(Process::CLOCK_MONOTONIC), nil)
    policy = File.join(@root, "policy.yml")
    File.write(policy, "{}")
    baseline_result = baseline.capture
    expect(baseline).to receive(:capture).with(phase: "require", offline: true, sinkhole: false, writes_only: true, env_profile: "dev", enforce: policy).and_return(baseline_result)
    allow(Bonebed::Enforcement).to receive(:load).with(policy, anything).and_return(read_paths: [], write_paths: [])
    expect(Bonebed::Session).to receive(:new).with(["true"], hash_including(unsetenv_others: true, offline: true, timeout: 2,
      output_limit: 12, argv_limit: 3, writes_only: true, enforcement: {read_paths: [], write_paths: []})).and_return(double(run: collector))
    runner = described_class.new(results_dir: File.join(@root, "results"), baseline:, offline: true, timeout: 2,
      output_limit: 12, argv_limit: 3, writes_only: true, enforce: policy)
    runner.run(["true"])
  end

  it "passes sinkhole to both the baseline and target session and records its mode" do
    result = baseline.capture
    expect(baseline).to receive(:capture).with(hash_including(sinkhole: true, offline: false)).and_return(result)
    expect(Bonebed::Session).to receive(:new).with(["true"], hash_including(sinkhole: true, offline: false))
      .and_return(double(run: Bonebed::Collector.new))
    observed = described_class.new(results_dir: File.join(@root, "results"), baseline:, sinkhole: true)
    path = observed.run(["true"])
    expect(JSON.parse(File.read(path)).dig("run", "mode", "sinkhole")).to be(true)
  end

  it "uses the same deny context for baseline and target and records its identity" do
    policy = File.join(@root, "deny.yml")
    File.write(policy, "{}")
    context = {"config" => {}, "name" => "command", "phase" => "exec"}
    result = baseline.capture
    expect(baseline).to receive(:capture).with(hash_including(deny: context)).and_return(result)
    expect(Bonebed::Session).to receive(:new).with(["true"], hash_including(deny: hash_including(context))).and_return(double(run: Bonebed::Collector.new))
    observed = described_class.new(results_dir: File.join(@root, "results"), baseline:, deny: policy)
    path = observed.run(["true"])
    expect(JSON.parse(File.read(path)).dig("run", "mode", "deny")).to eq(Bonebed::DenyPolicy.digest({}))
    expect { described_class.new(deny: policy, writes_only: true) }.to raise_error(ArgumentError, /writes.only/)
  end

  it "requires the CLI separator and forwards literal arguments after it" do
    allow(Bonebed::Doctor).to receive(:container?).and_return(true)
    expect { Bonebed::CLI.run_command(%w[ruby -e puts]) }.to raise_error(ArgumentError, /--/)
    expect { Bonebed::CLI.run_command(%w[--repeat 2 -- ruby]) }.to raise_error(ArgumentError, /repeat/)
    expect { Bonebed::CLI.run_command(%w[--jobs 2 -- ruby]) }.to raise_error(ArgumentError, /jobs/)
    fake = double(run: "manifest.json", last_errors: [], last_observer_errors: [])
    expect(described_class).to receive(:new).with(hash_including(timeout: 2, env_profile: "ci", sinkhole: true)).and_return(fake)
    expect(fake).to receive(:run).with(["ruby", "-e", "puts 1"]).and_return("manifest.json")
    allow(Bonebed::CLI).to receive(:summarize)
    expect { expect(Bonebed::CLI.run_command(["--timeout", "2", "--env-profile", "ci", "--sinkhole", "--", "ruby", "-e", "puts 1"])).to eq(0) }
      .to output("manifest.json\n").to_stdout
  end
end
