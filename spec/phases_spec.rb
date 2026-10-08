# frozen_string_literal: true

require "rubygems/package"
require "tmpdir"
require "fileutils"

RSpec.describe "isolated observation phases" do
  it "installs locally then requires a gem in one disposable environment" do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")
    Dir.mktmpdir do |root|
      FileUtils.mkdir_p(File.join(root, "lib"))
      File.write(File.join(root, "lib", "bonebed_probe.rb"), <<~RUBY)
        puts File.read(File.expand_path("~/.aws/credentials"))
        File.write("observed-project-write", "test")
        raise "inherited secret" if ENV["BONEBED_REAL_SECRET"]
      RUBY
      specification = Gem::Specification.new do |s|
        s.name = "bonebed-probe"
        s.version = "1.0.0"
        s.summary = "Fixture"
        s.authors = ["Bonebed"]
        s.homepage = "https://example.invalid"
        s.license = "MIT"
        s.files = ["lib/bonebed_probe.rb"]
      end
      package = Dir.chdir(root) { Gem::Package.build(specification) }
      prefetcher = double("prefetcher", call: [File.join(root, package)])
      ENV["BONEBED_REAL_SECRET"] = "must-not-reach-target"
      dig = Bonebed::Dig.new(results_dir: File.join(root, "results"), prefetcher:, quiet_target: true,
        baseline: Bonebed::Baseline.new(cache_dir: File.join(root, "baselines")))
      paths = dig.run("bonebed-probe", phase: "all", version: "1.0.0")
      manifests = paths.map { |path| JSON.parse(File.read(path)) }
      expect(manifests.map { |m| m["phase"] }).to eq(%w[install require])
      expect(manifests.map { |m| m.dig("run", "id") }.uniq.size).to eq(1)
      expect(manifests.map { |m| m["errors"] }).to all(be_empty)
      expect(manifests.first["network"]).to be_empty
      expect(manifests.last.dig("files", "notable")).to include("$HOME/.aws/credentials", "$PWD/observed-project-write")
      expect(manifests.last["canary_hits"]).to include(include("source" => ".aws/credentials", "seen_in" => "stdout"))
      expect(manifests.last["stdout"]).to include("[CANARY:")
      expect(File.exist?(File.join(Dir.pwd, "observed-project-write"))).to be(false)
    ensure
      ENV.delete("BONEBED_REAL_SECRET")
    end
  end

  it "keys baselines by phase and runtime, independently of project files" do
    baseline = Bonebed::Baseline.new
    require_id = baseline.send(:id, "require")
    expect(baseline.send(:id, "install")).not_to eq(require_id)
    Dir.mktmpdir do |root|
      Dir.chdir(root) do
        File.write("Gemfile.lock", "different project")
        expect(baseline.send(:id, "require")).to eq(require_id)
      end
    end
  end
end
