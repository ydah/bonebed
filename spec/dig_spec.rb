# frozen_string_literal: true

require "fileutils"
require "tmpdir"

RSpec.describe Bonebed::Dig do
  it "infers slash-separated require paths" do
    specification = instance_double(Gem::Specification, name: "seccomp-notify")
    allow(specification).to receive(:contains_requirable_file?) { |path| path == "seccomp/notify" }

    expect(Bonebed::Phase::Require.inferred_require_path(specification)).to eq("seccomp/notify")
  end

  it "infers a normalized top-level require path" do
    Dir.mktmpdir do |root|
      File.write(File.join(root, "active_support.rb"), "")
      specification = instance_double(Gem::Specification, name: "activesupport", full_require_paths: [root])
      allow(specification).to receive(:contains_requirable_file?).and_return(false)

      expect(Bonebed::Phase::Require.inferred_require_path(specification)).to eq("active_support")
    end
  end

  it "infers the only top-level file under the gemspec require path" do
    Dir.mktmpdir do |root|
      File.write(File.join(root, "yajl.rb"), "")
      specification = instance_double(Gem::Specification, name: "yajl-ruby", full_require_paths: [root])
      allow(specification).to receive(:contains_requirable_file?).and_return(false)

      expect(Bonebed::Phase::Require.inferred_require_path(specification)).to eq("yajl")
    end
  end

  it "does not invent a require path for an executable-only gem" do
    Dir.mktmpdir do |root|
      specification = instance_double(Gem::Specification, name: "grpc-tools", full_require_paths: [root])
      allow(specification).to receive(:contains_requirable_file?).and_return(false)

      expect(Bonebed::Phase::Require.inferred_require_path(specification)).to be_nil
    end
  end

  it "keeps project access notable and excludes the RubyGems cache" do
    observation = {
      files: {
        read: {"$PWD/config/demo.yml" => 1},
        write: {"$HOME/.cache/gem/spec.gemspec" => 1, "$HOME/.local/share/gem/specs/demo" => 1, "$HOME/.config/demo" => 1, "$PWD/log/demo.log" => 1}
      },
      network: {}, exec: {}, stats: {openat_total: 4, notify_roundtrips: 4, wall_ms: 1}, errors: [], stderr: ""
    }
    baseline = Bonebed::Baseline::Result.new(id: "test", observation: {files: {read: {}, write: {}}, network: {}, exec: {}})

    manifest = Bonebed::ManifestBuilder.call("demo", "1.0.0", "install", observation, baseline)

    expect(manifest.dig("files", "notable")).to eq(["$HOME/.config/demo", "$PWD/config/demo.yml", "$PWD/log/demo.log"])
    expect(manifest.dig("files", "write")).to include("$HOME/.cache/gem/spec.gemspec")
  end

  it "retries failed survey results" do
    Dir.mktmpdir do |results|
      path = File.join(results, "demo-1.0.0-require.json")
      dig = described_class.new(results_dir: results)
      File.write(path, JSON.generate(errors: ["failed"], gem: {name: "demo", version: "1.0.0"}, phase: "require", files: {read: [], write: []}))
      expect(dig.result_exists?("demo", phase: "require", version: "1.0.0")).to be(false)

      File.write(path, JSON.generate(errors: [], gem: {name: "demo", version: "1.0.0"}, phase: "require", files: {read: [], write: []}))
      expect(dig.result_exists?("demo", phase: "require", version: "1.0.0")).to be(true)

      File.write(path, JSON.generate(errors: [], gem: {name: "demo", version: "1.0.0", require_path: "demo/base"}, phase: "require", files: {read: [], write: []}))
      expect(dig.result_exists?("demo", phase: "require", version: "1.0.0", require_path: "demo/base")).to be(true)
      expect(dig.result_exists?("demo", phase: "require", version: "1.0.0", require_path: "demo/full")).to be(false)
    end
  end

  it "does not treat another gem with the same prefix as an existing result" do
    Dir.mktmpdir do |results|
      manifest = {gem: {name: "rack-test", version: "2.1.0"}, phase: "install", files: {read: [], write: []}, errors: []}
      File.write(File.join(results, "rack-test-2.1.0-install.json"), JSON.generate(manifest))
      dig = described_class.new(results_dir: results)

      expect(dig.result_exists?("rack", phase: "install")).to be(false)
      expect(dig.result_exists?("rack-test", phase: "install")).to be(true)
      File.write(File.join(results, "rack-1.0-install.json"), "{")
      expect(dig.result_exists?("rack", phase: "install")).to be(false)
    end
  end

  it "accepts dotted gem names and rejects invalid names" do
    Dir.mktmpdir do |results|
      dig = described_class.new(results_dir: results)
      expect(dig.result_exists?("jquery.fileupload-rails", phase: "install")).to be(false)
      ["../evil", "123", ".demo", "-demo", "_demo", "demo/evil", nil].each do |name|
        expect { dig.result_exists?(name, phase: "install") }.to raise_error(ArgumentError, "invalid gem name")
      end
    end
  end

  it "retries results with invalid manifest shapes or missing error status" do
    Dir.mktmpdir do |results|
      path = File.join(results, "demo-1.0.0-require.json")
      dig = described_class.new(results_dir: results)
      [nil, [], {gem: []}, {gem: {name: "demo", version: "1.0.0"}, phase: "require", files: {read: [], write: []}}, {gem: {name: "demo", version: "1.0.0"}, phase: "require", files: {read: [], write: []}, errors: nil},
        {gem: {name: "demo", version: "1.0.0"}, phase: "require", files: {read: [], write: []}, errors: ""}, {gem: {name: "demo", version: "1.0.0"}, phase: "require", files: {read: [], write: []}, errors: {}}].each do |manifest|
        File.write(path, JSON.generate(manifest))
        expect(dig.result_exists?("demo", phase: "require", version: "1.0.0")).to be(false), manifest.inspect
      end
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
