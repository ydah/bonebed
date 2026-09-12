# frozen_string_literal: true

require "fileutils"
require "tmpdir"

RSpec.describe Bonebed::Dig do
  it "infers slash-separated require paths" do
    specification = instance_double(Gem::Specification, name: "seccomp-notify")
    allow(specification).to receive(:contains_requirable_file?) { |path| path == "seccomp/notify" }

    expect(described_class.new.send(:inferred_require_path, specification)).to eq("seccomp/notify")
  end

  it "infers a normalized top-level require path" do
    Dir.mktmpdir do |root|
      File.write(File.join(root, "active_support.rb"), "")
      specification = instance_double(Gem::Specification, name: "activesupport", full_require_paths: [root])
      allow(specification).to receive(:contains_requirable_file?).and_return(false)

      expect(described_class.new.send(:inferred_require_path, specification)).to eq("active_support")
    end
  end

  it "excludes the RubyGems cache from notable files" do
    observation = {
      files: {read: {}, write: {"$HOME/.cache/gem/spec.gemspec" => 1, "$HOME/.config/demo" => 1}},
      network: {}, exec: {}, stats: {openat_total: 2, notify_roundtrips: 2, wall_ms: 1}, errors: [], stderr: ""
    }
    baseline = Bonebed::Baseline::Result.new(id: "test", observation: {files: {read: {}, write: {}}, network: {}, exec: {}})

    manifest = described_class.new.send(:manifest, "demo", "1.0.0", "install", observation, baseline)

    expect(manifest.dig("files", "notable")).to eq(["$HOME/.config/demo"])
    expect(manifest.dig("files", "write")).to include("$HOME/.cache/gem/spec.gemspec")
  end

  it "retries failed survey results" do
    Dir.mktmpdir do |results|
      path = File.join(results, "demo-1.0.0-require.json")
      dig = described_class.new(results_dir: results)
      File.write(path, JSON.generate(errors: ["failed"]))
      expect(dig.result_exists?("demo", phase: "require", version: "1.0.0")).to be(false)

      File.write(path, JSON.generate(errors: []))
      expect(dig.result_exists?("demo", phase: "require", version: "1.0.0")).to be(true)
    end
  end

  it "separates installed gem versions from platforms and lists dependencies" do
    Dir.mktmpdir do |gem_home|
      specifications = File.join(gem_home, "specifications")
      FileUtils.mkdir_p(specifications)
      File.write(File.join(specifications, "nokogiri-1.19.4-aarch64-linux-gnu.gemspec"),
        "# -*- encoding: utf-8 -*-\n# stub: nokogiri 1.19.4 aarch64-linux-gnu lib\n\n")
      File.write(File.join(specifications, "racc-1.8.1.gemspec"),
        "# -*- encoding: utf-8 -*-\n# stub: racc 1.8.1 ruby lib\n\n")

      expect(described_class.new.send(:installed_gems, gem_home)).to eq([
        {"name" => "nokogiri", "version" => "1.19.4", "platform" => "aarch64-linux-gnu"},
        {"name" => "racc", "version" => "1.8.1", "platform" => "ruby"}
      ])
    end
  end
end
