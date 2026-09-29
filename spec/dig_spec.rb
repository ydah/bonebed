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

  it "infers the only top-level file under the gemspec require path" do
    Dir.mktmpdir do |root|
      File.write(File.join(root, "yajl.rb"), "")
      specification = instance_double(Gem::Specification, name: "yajl-ruby", full_require_paths: [root])
      allow(specification).to receive(:contains_requirable_file?).and_return(false)

      expect(described_class.new.send(:inferred_require_path, specification)).to eq("yajl")
    end
  end

  it "does not invent a require path for an executable-only gem" do
    Dir.mktmpdir do |root|
      specification = instance_double(Gem::Specification, name: "grpc-tools", full_require_paths: [root])
      allow(specification).to receive(:contains_requirable_file?).and_return(false)

      expect(described_class.new.send(:inferred_require_path, specification)).to be_nil
    end
  end

  it "reads the resolved version from a downloaded gem after installation fails" do
    Dir.mktmpdir do |gem_home|
      path = File.join(gem_home, "cache", "demo-1.2.3.gem")
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, "gem")
      specification = instance_double(Gem::Specification, name: "demo", version: Gem::Version.new("1.2.3"))
      allow(Gem::Package).to receive(:new).with(path).and_return(instance_double(Gem::Package, spec: specification))

      expect(described_class.new.send(:cached_gem, gem_home, "demo")).to eq(specification)
    end
  end

  it "keeps project access notable and excludes the RubyGems cache" do
    observation = {
      files: {
        read: {"$PWD/config/demo.yml" => 1},
        write: {"$HOME/.cache/gem/spec.gemspec" => 1, "$HOME/.config/demo" => 1, "$PWD/log/demo.log" => 1}
      },
      network: {}, exec: {}, stats: {openat_total: 4, notify_roundtrips: 4, wall_ms: 1}, errors: [], stderr: ""
    }
    baseline = Bonebed::Baseline::Result.new(id: "test", observation: {files: {read: {}, write: {}}, network: {}, exec: {}})

    manifest = described_class.new.send(:manifest, "demo", "1.0.0", "install", observation, baseline)

    expect(manifest.dig("files", "notable")).to eq(["$HOME/.config/demo", "$PWD/config/demo.yml", "$PWD/log/demo.log"])
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

      File.write(path, JSON.generate(errors: [], gem: {require_path: "demo/base"}))
      expect(dig.result_exists?("demo", phase: "require", version: "1.0.0", require_path: "demo/base")).to be(true)
      expect(dig.result_exists?("demo", phase: "require", version: "1.0.0", require_path: "demo/full")).to be(false)
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

  it "exposes only the required gem and its runtime dependencies" do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")

    original_home = Gem.dir
    original_path = Gem.path
    original_env = ENV.values_at("GEM_HOME", "GEM_PATH")
    Dir.mktmpdir("bonebed-require-gems-") do |gem_home|
      install_fixture_gem(gem_home, "bonebed-runtime-dependency")
      install_fixture_gem(gem_home, "bonebed-unrelated")
      install_fixture_gem(gem_home, "bonebed-isolated", dependencies: ["bonebed-runtime-dependency"], body: <<~RUBY)
        raise "runtime dependency missing" unless Gem::Specification.find_all_by_name("bonebed-runtime-dependency").any?
        raise "unrelated gem leaked" if Gem::Specification.find_all_by_name("bonebed-unrelated").any?
      RUBY
      ENV["GEM_HOME"] = gem_home
      ENV["GEM_PATH"] = gem_home
      Gem.use_paths(gem_home, [gem_home])
      Gem::Specification.reset
      probe = described_class.new
      baseline = Bonebed::Baseline::Result.new(id: "test", observation: probe.send(:empty_observation))
      dig = described_class.new(results_dir: File.join(gem_home, "results"), baseline: instance_double(Bonebed::Baseline, capture: baseline))

      path = dig.run("bonebed-isolated", phase: "require", version: "1.0.0", require_path: "bonebed-isolated")
      manifest = JSON.parse(File.read(path))

      expect(manifest.fetch("errors")).to be_empty
    end
  ensure
    ENV["GEM_HOME"], ENV["GEM_PATH"] = original_env
    Gem.use_paths(original_home, original_path)
    Gem::Specification.reset
  end

  def install_fixture_gem(gem_home, name, dependencies: [], body: "")
    gem_dir = File.join(gem_home, "gems", "#{name}-1.0.0")
    FileUtils.mkdir_p([File.join(gem_dir, "lib"), File.join(gem_home, "specifications")])
    File.write(File.join(gem_dir, "lib", "#{name}.rb"), body)
    specification = Gem::Specification.new do |spec|
      spec.name = name
      spec.version = "1.0.0"
      spec.summary = name
      spec.authors = ["Bonebed"]
      spec.files = ["lib/#{name}.rb"]
      spec.require_paths = ["lib"]
      dependencies.each { |dependency| spec.add_runtime_dependency(dependency, "= 1.0.0") }
    end
    File.write(File.join(gem_home, "specifications", "#{specification.full_name}.gemspec"), specification.to_ruby)
  end
end
