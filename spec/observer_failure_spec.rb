# frozen_string_literal: true

require "bonebed/cli"
require "bonebed/bundle_runner"
require "bonebed/sinkhole"

RSpec.describe "fatal observer failures" do
  before { allow(Bonebed::Doctor).to receive(:container?).and_return(true) }

  it "classifies baseline target and setup failures as observer failures" do
    Dir.mktmpdir do |cache_dir|
      baseline = Bonebed::Baseline.new(cache_dir:)
      observation = Bonebed::Collector.new.snapshot(Bonebed::PathNormalizer.new).merge(errors: ["empty baseline failed"])
      allow(baseline).to receive(:observe).and_return(observation)
      expect { baseline.capture }.to raise_error(Bonebed::ObserverError, /empty baseline failed/)
      allow(baseline).to receive(:observe).and_raise(Errno::EPERM, "namespace")
      expect { baseline.capture(sinkhole: true) }.to raise_error(Bonebed::ObserverError, /namespace/)
      expect(Dir.children(cache_dir)).to be_empty
    end
  end

  it "exits two without executing command targets when isolation is unavailable" do
    expect(Bonebed::Sinkhole::Unavailable).to be < Bonebed::ObserverError
    allow_any_instance_of(Bonebed::Baseline).to receive(:capture).and_raise(Bonebed::ObserverError, "namespace unavailable")
    expect(Bonebed::Session).not_to receive(:new)
    expect { expect(Bonebed::CLI.start(%w[run --sinkhole -- must-not-run])).to eq(2) }.to output(/namespace unavailable/).to_stderr
  end

  it "records observer-only Dig failures and never resumes them" do
    Dir.mktmpdir do |results_dir|
      dig = Bonebed::Dig.new(results_dir:)
      path = dig.write_failure("demo", version: "1", phase: "require", error: Bonebed::ObserverError.new("namespace unavailable"))
      manifest = JSON.parse(File.read(path))
      expect(manifest.fetch("errors")).to be_empty
      expect(manifest.fetch("observer_errors").join).to include("namespace unavailable")
      expect(manifest.fetch("failure_reason")).to eq("observation_failed")
      expect(manifest.dig("target", "exit_status")).to be_nil
      expect(Bonebed::ResultStore.new(results_dir).exists?("demo", version: "1", phase: "require")).to be(false)
    end
  end

  it "saves bundle baseline failures as observer failures and exits two without strict" do
    Dir.mktmpdir do |root|
      gemfile = File.join(root, "Gemfile")
      marker = File.join(root, "must-not-run")
      File.write(gemfile, "File.write(#{marker.inspect}, 'wrong')")
      File.write("#{gemfile}.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n\nBUNDLED WITH\n   #{Bundler::VERSION}\n")
      runner = Bonebed::BundleRunner.new(results_dir: File.join(root, "results"), sinkhole: true)
      allow(runner).to receive(:capture_baseline).and_raise(Bonebed::ObserverError, "namespace unavailable")
      expect(Bonebed::Session).not_to receive(:new)
      allow(Bonebed::BundleRunner).to receive(:new).and_return(runner)
      expect { expect(Bonebed::CLI.start(["bundle", "--sinkhole", "--gemfile", gemfile])).to eq(2) }.to output.to_stdout.and output.to_stderr
      manifest = Bonebed::ResultStore.read(File.join(root, "results")).fetch(0)
      expect(manifest.fetch("errors")).to be_empty
      expect(manifest.fetch("observer_errors").join).to include("namespace unavailable")
      expect(manifest.fetch("failure_reason")).to eq("observation_failed")
      expect(File).not_to exist(marker)
    end
  end

  [false, true].each do |isolate|
    it "continues after observer failures with isolate=#{isolate} and preserves target failure priority" do
      dig = Object.new
      dig.define_singleton_method(:result_exists?) { |*| false }
      dig.define_singleton_method(:write_failure) { |*| nil }
      dig.define_singleton_method(:run) do |name, **|
        raise Bonebed::ObserverError, "namespace unavailable" if name == "observer"

        @target_failed = name == "target"
      end
      dig.define_singleton_method(:last_errors) { @target_failed ? ["target failed"] : [] }
      dig.define_singleton_method(:last_observer_errors) { [] }
      survey = Bonebed::Survey.new(dig:, output: StringIO.new, isolate:)
      expect(survey.run([{name: "observer"}, {name: "safe"}], phase: "require")).to be(false)
      expect(survey.fatal_observer_error?).to be(true)
      expect(survey.target_failed?).to be(false)
      expect(survey.last_observer_errors.join).to include("namespace unavailable")
      expect(survey.run([{name: "observer"}, {name: "target"}], phase: "require")).to be(false)
      expect(survey.fatal_observer_error?).to be(true)
      expect(survey.target_failed?).to be(true)
    end
  end

  it "uses observer exit two for survey and gemfile dig, with target failure exit one taking priority" do
    survey = double(run: false, last_observer_errors: ["namespace unavailable"], fatal_observer_error?: true, target_failed?: false)
    allow(Bonebed::Survey).to receive(:new).and_return(survey)
    allow(Bonebed::Survey).to receive(:file).and_return([{name: "demo"}])
    allow(Bonebed::Survey).to receive(:lockfile).and_return([{name: "demo"}])
    allow(Bonebed::Dig).to receive(:new).and_return(double)
    [%w[survey --file gems.txt], %w[dig --gemfile Gemfile.lock]].each do |command|
      expect { expect(Bonebed::CLI.start(command.dup)).to eq(2) }.to output(/namespace unavailable/).to_stderr
      allow(survey).to receive(:target_failed?).and_return(true)
      expect { expect(Bonebed::CLI.start(command.dup)).to eq(1) }.to output(/namespace unavailable/).to_stderr
      allow(survey).to receive(:target_failed?).and_return(false)
    end
  end
end
