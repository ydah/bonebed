# frozen_string_literal: true

require "bonebed/phase/bundler_plugin"
require "bonebed/phase/install"
require "rubygems/package"
require "json_schemer"

RSpec.describe Bonebed::Phase::BundlerPlugin do
  around do |example|
    Dir.mktmpdir("bundler-phase-fixtures-") do |directory|
      @packages = %w[dependency plugin].map do |name|
        source = File.expand_path("fixtures/gems/bundler-plugin/#{name}", __dir__)
        specification = Gem::Specification.load(File.join(source, "fixture.gemspec"))
        path = File.join(directory, "#{specification.full_name}.gem")
        Dir.chdir(source) { Gem::DefaultUserInteraction.use_ui(Gem::SilentUI.new) { Gem::Package.build(specification, false, false, path) } }
        path
      end
      @specification = Gem::Package.new(@packages.last).spec
      Bonebed::GemEnvironment.open do |environment|
        @environment = environment
        example.run
      end
    end
  end

  it "registers the packaged plugin through Bundler and observes its loaded dependency in disposable paths" do
    installed = Bonebed::Phase::Install.call(@environment, @packages, quiet_target: true, timeout: 20)
    expect(installed.errors).to be_empty
    marker = File.join(@environment.home, ".bundler-plugin-probe")
    dependency_marker = File.join(@environment.project, "bundler-dependency-loaded")
    expect(File).not_to exist(marker)
    expect(File).not_to exist(dependency_marker)
    # A real user's --cwd may contain an untrusted Gemfile. Bootstrap must select its own empty file.
    File.write(File.join(@environment.project, "Gemfile"), "raise 'host Gemfile evaluated'\n")

    collector = described_class.call(@environment, @specification, packages: @packages, quiet_target: true, timeout: 20)
    snapshot = collector.snapshot(@environment.normalizer)
    expect(snapshot[:errors]).to be_empty, snapshot[:stderr]
    expect(snapshot[:observer_errors]).to be_empty
    expect(snapshot[:network]).to be_empty
    expect(snapshot[:files][:write].keys).to include("$HOME/.bundler-plugin-probe", "$PWD/bundler-dependency-loaded")
    expect(snapshot[:files][:read].keys).to include("$GEM_HOME/gems/bonebed-bundler-probe-1.0.0/plugins.rb")
    index = File.join(described_class.plugin_root(@environment), "index")
    expect(File.read(index)).to include("bonebed-fixture-noop", "bonebed-bundler-probe")
    expect(File.read(marker)).to eq(Bundler::VERSION)
    expect(File.read(dependency_marker)).to eq("dependency ran inside the observed target")
    expect(@environment.env).not_to have_key("BUNDLE_GEMFILE")
  end

  it "fails explicitly for a package without a root plugins.rb entrypoint" do
    specification = Gem::Package.new(@packages.first).spec
    expect { described_class.call(@environment, specification, packages: @packages, quiet_target: true) }
      .to raise_error(ArgumentError, /plugins.rb/)
  end

  it "keeps a plugin load exception as an observed target failure" do
    installed = Bonebed::Phase::Install.call(@environment, @packages, quiet_target: true, timeout: 20)
    expect(installed.errors).to be_empty
    @environment.env["BONEBED_PLUGIN_RAISE"] = "1"
    collector = described_class.call(@environment, @specification, packages: @packages, quiet_target: true, timeout: 20)
    snapshot = collector.snapshot(@environment.normalizer)
    expect(snapshot[:target][:exit_status]).not_to eq(0)
    expect(snapshot[:errors]).not_to be_empty
    expect(snapshot[:observer_errors]).to be_empty
    expect(snapshot[:stderr]).to include("fixture plugin failure")
  end

  it "links the Bundler phase into all, validates schema, and requires it before resuming" do
    baseline = Bonebed::Baseline.new(cache_dir: File.join(@environment.root, "baselines"))
    prefetcher = ->(*) { @packages }
    dig = Bonebed::Dig.new(results_dir: File.join(@environment.root, "results"), baseline:, prefetcher:, quiet_target: true)
    paths = dig.run(@specification.name, version: @specification.version.to_s, phase: "all")
    manifests = paths.map { |path| Bonebed::ResultStore.load(path) }
    expect(manifests.map { |manifest| manifest.fetch("phase") }).to eq(%w[install bundler_plugin require])
    schema = JSONSchemer.schema(Pathname.new(File.expand_path("../schema/manifest-v2.json", __dir__)))
    manifests.each do |manifest|
      expect(manifest.dig("gem", "bundler_plugin")).to be(true)
      expect(manifest.dig("gem", "rubygems_plugin")).to be(false)
      expect(manifest["errors"]).to be_empty
      expect(manifest["observer_errors"]).to be_empty
      expect(schema.validate(manifest).to_a).to be_empty
    end
    expect(manifests[1].dig("files", "write")).to include("$HOME/.bundler-plugin-probe")
    expect(manifests[1].dig("environment", "bundler")).to eq(Bundler::VERSION)
    expect(manifests.last.dig("files", "write")).not_to include("$HOME/.bundler-plugin-probe")
    expect(dig.result_exists?(@specification.name, phase: "all", version: "1.0.0")).to be(true)
    other_runtime = Marshal.load(Marshal.dump(manifests[1]))
    other_runtime["environment"]["bundler"] = "0.0.0"
    other_path = Bonebed::ResultStore.new(File.join(@environment.root, "results")).write(other_runtime)
    expect(other_path).not_to eq(paths[1])
    File.unlink(paths[1])
    expect(dig.result_exists?(@specification.name, phase: "all", version: "1.0.0")).to be(false)
  end

  it "persists an observer failure under the actual Bundler phase instead of the successful install" do
    empty = Bonebed::Collector.new.snapshot(@environment.normalizer)
    baseline = double(capture: Bonebed::Baseline::Result.new(id: "fixture", observation: empty))
    allow(baseline).to receive(:capture).with(hash_including(phase: "bundler_plugin")).and_raise(Bonebed::ObserverError, "fixture bootstrap unavailable")
    results = File.join(@environment.root, "results")
    dig = Bonebed::Dig.new(results_dir: results, baseline:, prefetcher: ->(*) { @packages }, quiet_target: true)
    expect { dig.run(@specification.name, version: "1.0.0", phase: "all") }.to raise_error(Bonebed::ObserverError)
    manifests = Bonebed::ResultStore.read(results)
    expect(manifests.find { |manifest| manifest["phase"] == "install" }.fetch("observer_errors")).to be_empty
    failure = manifests.find { |manifest| manifest["phase"] == "bundler_plugin" }
    expect(failure.fetch("failure_reason")).to eq("observation_failed")
    expect(failure.fetch("observer_errors")).to include(include("fixture bootstrap unavailable"))
  end
end
