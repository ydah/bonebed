# frozen_string_literal: true

require "bonebed/dig"
require "bonebed/command_runner"
require "bonebed/bundle_runner"

RSpec.describe "sinkhole observation options" do
  it "rejects incompatible modes before starting any observer" do
    [Bonebed::Dig, Bonebed::CommandRunner, Bonebed::BundleRunner].each do |runner|
      expect { runner.new(sinkhole: true, offline: true) }.to raise_error(ArgumentError, /offline.*sinkhole|sinkhole.*offline/)
      expect { runner.new(sinkhole: true, trace: "trace") }.to raise_error(ArgumentError, /trace/)
      expect { runner.new(sinkhole: "true") }.to raise_error(ArgumentError, /boolean/)
    end
    expect { Bonebed::Baseline.new.capture(sinkhole: true, offline: true) }.to raise_error(ArgumentError, /offline.*sinkhole|sinkhole.*offline/)
  end

  it "uses matching sinkhole baseline options for every Dig phase" do
    baseline = instance_double(Bonebed::Baseline)
    %w[install require plugin bundler_plugin].each do |phase|
      expect(baseline).to receive(:capture).with(hash_including(phase:, sinkhole: true, offline: false))
    end
    dig = Bonebed::Dig.new(sinkhole: true, baseline:)
    expect(dig.observation_mode).to include("sinkhole" => true)
    dig.prepare_baselines(phase: "all")
  end

  it "keeps sinkhole baseline caches separate and forwards the mode to observation" do
    Dir.mktmpdir do |cache_dir|
      baseline = Bonebed::Baseline.new(cache_dir:)
      observation = Bonebed::Collector.new.snapshot(Bonebed::PathNormalizer.new)
      expect(baseline).to receive(:observe).with("require", hash_including(sinkhole: false)).and_return(observation)
      ordinary = baseline.capture
      expect(baseline).to receive(:observe).with("require", hash_including(sinkhole: true)).and_return(observation)
      captured = baseline.capture(sinkhole: true)
      expect(captured.id).not_to eq(ordinary.id)
      expect(baseline.capture(sinkhole: true).id).to eq(captured.id)
    end
  end

  it "forwards sinkhole to the baseline Session through the require phase" do
    collector = Bonebed::Collector.new
    expect(Bonebed::Phase::Require).to receive(:call).with(anything, anything,
      hash_including(sinkhole: true, offline: false)).and_return([collector, "bonebed_baseline_empty"])
    Dir.mktmpdir { |cache_dir| Bonebed::Baseline.new(cache_dir:).capture(sinkhole: true) }
  end

  it "does not tolerate or cache isolation failure in a sinkhole baseline" do
    Dir.mktmpdir do |cache_dir|
      collector = Bonebed::Collector.new
      collector.record_observer_error(:isolation, Bonebed::Error.new("network namespace unavailable"))
      baseline = Bonebed::Baseline.new(cache_dir:)
      allow(baseline).to receive(:observe).and_return(collector.snapshot(Bonebed::PathNormalizer.new))
      expect { baseline.capture(sinkhole: true) }.to raise_error(Bonebed::Error, /network namespace unavailable/)
      expect(Dir.children(cache_dir)).to be_empty
    end
  end
end
