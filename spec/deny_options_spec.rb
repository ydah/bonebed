# frozen_string_literal: true

require "bonebed/cli"

RSpec.describe "deny observation options" do
  it "keys baseline caches by complete policy, gem and phase context" do
    Dir.mktmpdir do |directory|
      baseline = Bonebed::Baseline.new(cache_dir: directory)
      config = Bonebed::DenyPolicy.context({}, name: "example", phase: "require")
      result = Bonebed::Collector.new.snapshot(Bonebed::PathNormalizer.new)
      expect(baseline).to receive(:observe).with("require", hash_including(deny: config)).and_return(result)
      first = baseline.capture(deny: config)
      expect(baseline.capture(deny: config).id).to eq(first.id)
      %w[name phase].each do |field|
        other = config.merge(field => ((field == "name") ? "other" : "exec"))
        expect(baseline).to receive(:observe).with("require", hash_including(deny: other)).and_return(result)
        expect(baseline.capture(deny: other).id).not_to eq(first.id)
      end
      expect(baseline.send(:id)).not_to eq(first.id)
    end
  end

  it "passes deny through baseline observation and rejects writes-only capture" do
    config = Bonebed::DenyPolicy.context({}, name: "example", phase: "exec")
    expect(Bonebed::Phase::Require).to receive(:call).with(anything, anything, hash_including(deny: hash_including(config)))
      .and_return([Bonebed::Collector.new, "bonebed_baseline_empty"])
    Dir.mktmpdir { |directory| Bonebed::Baseline.new(cache_dir: directory).capture(deny: config) }
    expect { Bonebed::Baseline.new.capture(deny: config, writes_only: true) }.to raise_error(ArgumentError, /writes.only/)
  end

  it "uses a loaded policy snapshot for Dig identity and each gem phase context" do
    Tempfile.create(["deny", ".yml"]) do |file|
      file.write("{}")
      file.flush
      dig = Bonebed::Dig.new(deny: file.path)
      mode = dig.observation_mode
      file.rewind
      file.write("rules: {disable: [credential-read]}")
      file.flush
      expect(dig.observation_mode).to eq(mode)
      expect(mode.fetch("deny")).to eq(Bonebed::DenyPolicy.digest({}))
      specification = Gem::Specification.new { |spec|
        spec.name = "example"
        spec.version = "1.0.0"
      }
      %w[install require plugin exec].each do |phase|
        expect(dig.send(:session_options, phase, specification)[:deny]).to eq(Bonebed::DenyPolicy.context({}, name: "example", phase:))
      end
      expect { Bonebed::Dig.new(deny: file.path, writes_only: true) }.to raise_error(ArgumentError, /writes.only/)
    end
  end

  it "forwards CLI denial options without mixing warnings into stdout" do
    fake = double(run: "manifest.json", last_errors: [], last_observer_errors: [])
    expect(Bonebed::CommandRunner).to receive(:new).with(hash_including(deny: "policy.yml")).and_return(fake)
    allow(Bonebed::CLI).to receive(:summarize)
    allow(Bonebed::Doctor).to receive(:container?).and_return(true)
    expect { expect(Bonebed::CLI.run_command(%w[--deny policy.yml -- true])).to eq(0) }
      .to output("manifest.json\n").to_stdout.and output(/best.effort.*not.*boundary/i).to_stderr
  end

  it "observes an install and require with matching deny baselines and saved evidence" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")
    Dir.mktmpdir do |root|
      FileUtils.mkdir_p(File.join(root, "lib"))
      File.write(File.join(root, "lib", "deny_probe.rb"), 'begin; File.read(File.join(ENV.fetch("HOME"), ".aws/credentials")); rescue Errno::EPERM; puts "fixture denied"; end')
      specification = Gem::Specification.new do |spec|
        spec.name = "deny-probe"
        spec.version = "1.0.0"
        spec.summary = "Local denial fixture"
        spec.authors = ["Bonebed"]
        spec.files = ["lib/deny_probe.rb"]
      end
      package = Dir.chdir(root) { Gem::DefaultUserInteraction.use_ui(Gem::SilentUI.new) { Gem::Package.build(specification) } }
      policy = File.join(root, "policy.yml")
      File.write(policy, "{}")
      dig = Bonebed::Dig.new(results_dir: File.join(root, "results"), deny: policy, quiet_target: true,
        baseline: Bonebed::Baseline.new(cache_dir: File.join(root, "baselines")), prefetcher: double(call: [File.join(root, package)]))
      results = Array(dig.run("deny-probe", phase: "all", version: "1.0.0")).map { |path| JSON.parse(File.read(path)) }
      expect(results.map { |manifest| manifest["phase"] }).to eq(%w[install require])
      expect(results.map { |manifest| manifest["errors"] }).to all(be_empty)
      expect(results.map { |manifest| manifest["observer_errors"] }).to all(be_empty)
      expect(results.last["stdout"]).to include("fixture denied")
      expect(results.last["denied"]).to include(include("capability" => "file:read:$HOME/.aws/credentials"))
      expect(results.map { |manifest| manifest.dig("run", "mode", "deny") }).to all(eq(Bonebed::DenyPolicy.digest({})))
    end
  end

  it "matches temporary paths using the same normalization as saved manifests" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")
    Dir.mktmpdir do |root|
      config = {"rules" => {"custom" => [{"id" => "temp-write", "severity" => "high", "match" => ["file:write:$TMPDIR/<random>/named"]}]}}
      policy = File.join(root, "policy.yml")
      File.write(policy, config.to_yaml)
      runner = Bonebed::CommandRunner.new(results_dir: File.join(root, "results"), deny: policy, quiet_target: true,
        baseline: Bonebed::Baseline.new(cache_dir: File.join(root, "baselines")))
      code = 'begin; File.write(File.join(ENV.fetch("TMPDIR"), "named"), "bad"); abort "allowed"; rescue Errno::EPERM; puts "denied"; end'
      manifest = JSON.parse(File.read(runner.run([RbConfig.ruby, "-e", code])))
      expect(manifest["stdout"]).to eq("denied\n")
      expect(manifest["errors"]).to be_empty
      expect(manifest["observer_errors"]).to be_empty
      expect(manifest["denied"]).to include(include("capability" => "file:write:$TMPDIR/<random>/named"))
    end
  end
end
