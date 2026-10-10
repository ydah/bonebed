# frozen_string_literal: true

require "bonebed/bundle_runner"
require "rubygems/package"

RSpec.describe Bonebed::BundleRunner do
  around do |example|
    Dir.mktmpdir("bundle-observation-") do |root|
      @root = root
      @gemfile = File.join(root, "Gemfile")
      @lockfile = "#{@gemfile}.lock"
      example.run
    end
  end

  def write_inputs(body = "")
    File.write(@gemfile, "source 'https://rubygems.org'\ngem 'bonebed-bundle-probe', '= 1.0.0'\n#{body}\n")
    File.write(@lockfile, <<~LOCK)
      GEM
        remote: https://rubygems.org/
        specs:
          bonebed-bundle-probe (1.0.0)

      PLATFORMS
        ruby

      DEPENDENCIES
        bonebed-bundle-probe (= 1.0.0)

      BUNDLED WITH
         #{Bundler::VERSION}
    LOCK
  end

  def build_package
    source = File.join(@root, "package")
    FileUtils.mkdir_p(File.join(source, "lib"))
    File.write(File.join(source, "lib", "bonebed_bundle_probe.rb"), "")
    spec = Gem::Specification.new do |item|
      item.name = "bonebed-bundle-probe"
      item.version = "1.0.0"
      item.summary = "Fixture"
      item.authors = ["Bonebed"]
      item.license = "MIT"
      item.homepage = "https://example.invalid"
      item.required_ruby_version = ">= 3.2"
      item.files = ["lib/bonebed_bundle_probe.rb"]
    end
    filename = Dir.chdir(source) { Gem::Package.build(spec) }
    File.join(source, filename)
  end

  it "observes a local install with disposable project configuration and no inherited secrets" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")

    write_inputs('raise "host secret inherited" if ENV["BONEBED_BUNDLE_SECRET"]; File.write("gemfile-evaluated", "yes")')
    original = File.binread(@lockfile)
    package = build_package
    prefetcher = double("prefetcher")
    expect(prefetcher).to receive(:call).with("bonebed-bundle-probe", "1.0.0", platform: "ruby").and_return([package])
    previous = ENV["BONEBED_BUNDLE_SECRET"]
    ENV["BONEBED_BUNDLE_SECRET"] = "do-not-inherit"
    runner = described_class.new(results_dir: File.join(@root, "results"), quiet_target: true, prefetcher:)
    manifest = JSON.parse(File.read(runner.run(gemfile: @gemfile)))
    expect(manifest.fetch("errors")).to be_empty
    expect(manifest.dig("target", "exit_status")).to eq(0)
    expect(manifest.dig("run", "kind")).to eq("bundle")
    expect(manifest.fetch("dependencies")).to include(include("name" => "bonebed-bundle-probe", "version" => "1.0.0"))
    expect(manifest.dig("files", "write")).to include("$PWD/gemfile-evaluated")
    expect(manifest.fetch("command")).to include("install", "--local")
    expect(manifest.dig("bundle", "lockfile_sha256")).to eq(Digest::SHA256.hexdigest(original))
    expect(File.binread(@lockfile)).to eq(original)
    expect(File).not_to exist(File.join(@root, "gemfile-evaluated"))
    expect(File).not_to exist(File.join(@root, ".bundle"))
    expect(runner.last_errors).to be_empty
  ensure
    previous ? ENV["BONEBED_BUNDLE_SECRET"] = previous : ENV.delete("BONEBED_BUNDLE_SECRET")
  end

  it "records prefetch failure without evaluating the Gemfile" do
    marker = File.join(@root, "must-not-run")
    write_inputs("File.write(#{marker.inspect}, 'wrong')")
    prefetcher = double("prefetcher")
    allow(prefetcher).to receive(:call).and_raise(Bonebed::Prefetcher::Error, "registry unavailable")
    runner = described_class.new(results_dir: File.join(@root, "results"), prefetcher:)
    manifest = JSON.parse(File.read(runner.run(gemfile: @gemfile)))
    expect(manifest.fetch("errors").join).to include("registry unavailable")
    expect(manifest.fetch("failure_reason")).to eq("prefetch_failed")
    expect(runner.last_errors).not_to be_empty
    expect(File).not_to exist(marker)
  end

  it "refuses matching Gemfile operations using the aggregate bundle identity" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")
    write_inputs('begin; File.write("blocked", "bad"); rescue Errno::EPERM; puts "fixture denied"; end')
    package = build_package
    policy = File.join(@root, "deny.yml")
    File.write(policy, {"rules" => {"custom" => [{"id" => "fixture-write", "severity" => "high", "match" => ["file:write:$PWD/blocked"]}]}}.to_yaml)
    runner = described_class.new(results_dir: File.join(@root, "results"), deny: policy, quiet_target: true,
      prefetcher: double("prefetcher", call: [package]))
    manifest = JSON.parse(File.read(runner.run(gemfile: @gemfile)))
    expect(manifest.fetch("errors")).to be_empty
    expect(manifest.fetch("observer_errors")).to be_empty
    expect(manifest.fetch("denied")).to include(include("capability" => "file:write:$PWD/blocked", "rule_id" => "fixture-write"))
    expect(manifest.dig("run", "mode", "deny")).to match(/\A[0-9a-f]{64}\z/)
    expect { described_class.new(deny: policy, writes_only: true) }.to raise_error(ArgumentError, /writes.only/)
  end

  it "passes sinkhole to both bundle baseline and target sessions" do
    write_inputs
    package = build_package
    expect(Bonebed::Session).to receive(:new).with(anything, hash_including(sinkhole: true, offline: false))
      .twice.and_return(double(run: Bonebed::Collector.new))
    runner = described_class.new(results_dir: File.join(@root, "results"), sinkhole: true,
      prefetcher: double("prefetcher", call: [package]))
    manifest = JSON.parse(File.read(runner.run(gemfile: @gemfile)))
    expect(manifest.fetch("errors")).to be_empty
    expect(manifest.dig("run", "mode", "sinkhole")).to be(true)
  end

  it "uses the verified stdlib Bundler when its default gem directory is absent" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")
    source = Bundler.method(:root).source_location.first
    standard_library = File.join(RbConfig::CONFIG.fetch("rubylibdir"), "bundler.rb")
    skip "the active Bundler is installed separately from Ruby" unless File.identical?(source, standard_library)

    write_inputs
    package = build_package
    specification = Gem.loaded_specs.fetch("bundler")
    allow(specification).to receive(:default_gem?).and_return(true)
    allow(specification).to receive(:full_gem_path).and_return(File.join(@root, "missing-default-bundler"))
    expect_any_instance_of(Bonebed::GemEnvironment).not_to receive(:copy_specification)
    runner = described_class.new(results_dir: File.join(@root, "results"), quiet_target: true,
      prefetcher: double("prefetcher", call: [package]))
    manifest = JSON.parse(File.read(runner.run(gemfile: @gemfile)))
    expect(manifest.fetch("errors")).to be_empty
    expect(manifest.dig("target", "exit_status")).to eq(0)
  end

  it "does not fall back for missing nondefault Bundler or a mismatched runtime source" do
    specification = Gem.loaded_specs.fetch("bundler")
    allow(specification).to receive(:full_gem_path).and_return(File.join(@root, "missing-bundler"))
    allow(specification).to receive(:default_gem?).and_return(false)
    runner = described_class.new
    Bonebed::GemEnvironment.open do |environment|
      expect(environment).to receive(:copy_specification).with(specification).and_raise(Errno::ENOENT)
      expect { runner.send(:configure, environment) }.to raise_error(Errno::ENOENT)
      allow(specification).to receive(:default_gem?).and_return(true)
      allow(Bundler).to receive(:method).with(:root).and_return(double(source_location: [File.join(@root, "unverified.rb"), 1]))
      expect { runner.send(:configure, environment) }.to raise_error(Bonebed::Error, /Bundler runtime/)
    end
  end

  it "uses verified stdlib Bundler for a specification synthesized by Bundler metadata" do
    source = Bundler.method(:root).source_location.first
    standard_library = File.join(RbConfig::CONFIG.fetch("rubylibdir"), "bundler.rb")
    skip "the active Bundler is installed separately from Ruby" unless File.identical?(source, standard_library)

    loaded = Gem.loaded_specs.dup
    loaded.delete("bundler")
    allow(Gem).to receive(:loaded_specs).and_return(loaded)
    metadata = Bundler::Source::Metadata.new
    metadata.specs.each { |spec| loaded["bundler"] = spec if spec.name == "bundler" }
    specification = loaded.fetch("bundler")
    if specification.default_gem?
      # Bundler 4 finds the installed default spec; reproduce Bundler 2's metadata layout.
      specification = Gem::Specification.new("bundler", Bundler::VERSION)
      specification.loaded_from = File.join(RbConfig::CONFIG.fetch("rubylibdir"), "bundler", "source")
      specification.source = metadata
      loaded["bundler"] = specification
    end
    expect(specification.default_gem?).to be(false)
    expect(File).not_to be_directory(specification.full_gem_path)
    expect(specification.loaded_from).to eq(File.join(RbConfig::CONFIG.fetch("rubylibdir"), "bundler", "source"))

    write_inputs
    package = build_package
    runner = described_class.new(results_dir: File.join(@root, "results"), quiet_target: true,
      prefetcher: double("prefetcher", call: [package]))
    manifest = JSON.parse(File.read(runner.run(gemfile: @gemfile)))
    expect(manifest.fetch("errors")).to be_empty
    expect(manifest.dig("target", "exit_status")).to eq(0)
  end

  it "copies the active Bundler without resolving a different same-version default specification" do
    specification = Gem.loaded_specs.fetch("bundler")
    source = File.join(@root, "active-bundler")
    FileUtils.mkdir_p(source)
    File.write(File.join(source, "bundler.rb"), "active runtime")
    gemspec = File.join(@root, "bundler.gemspec")
    File.write(gemspec, specification.to_ruby)
    allow(specification).to receive_messages(full_gem_path: source, loaded_from: gemspec,
      default_gem?: false, extension_dir: File.join(@root, "no-extensions"))
    alternate = specification.dup
    allow(alternate).to receive(:full_gem_path).and_return(File.join(@root, "missing-default-bundler"))
    allow(Gem::Resolver).to receive(:for_current_gems).and_return(double(resolve: [double(spec: alternate)]))

    Bonebed::GemEnvironment.open do |environment|
      described_class.new.send(:configure, environment)
      expect(File.read(File.join(environment.gem_home, "gems", specification.full_name, "bundler.rb"))).to eq("active runtime")
    end
  end

  it "records Gemfile execution failures as target failures" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")

    write_inputs('raise "target gemfile failure"')
    package = build_package
    runner = described_class.new(results_dir: File.join(@root, "results"), quiet_target: true,
      prefetcher: double("prefetcher", call: [package]))
    manifest = JSON.parse(File.read(runner.run(gemfile: @gemfile)))
    expect(manifest.fetch("failure_reason")).to eq("bundle_install_failed")
    expect(manifest.fetch("stderr")).to include("target gemfile failure")
    expect(manifest.dig("target", "exit_status")).not_to eq(0)
    expect(runner.last_errors).not_to be_empty
  end

  it "does not substitute a different version for a locked dependency" do
    write_inputs
    package = build_package
    File.write(@lockfile, File.read(@lockfile).gsub("1.0.0", "2.0.0"))
    runner = described_class.new(results_dir: File.join(@root, "results"), prefetcher: double("prefetcher", call: [package]))
    manifest = JSON.parse(File.read(runner.run(gemfile: @gemfile)))
    expect(manifest.fetch("failure_reason")).to eq("prefetch_failed")
    expect(manifest.fetch("errors").join).to include("bonebed-bundle-probe-2.0.0")
  end

  it "rejects path, git and unsupported registry locks before downloading or executing anything" do
    write_inputs
    prefetcher = double("prefetcher")
    expect(prefetcher).not_to receive(:call)
    runner = described_class.new(results_dir: File.join(@root, "results"), prefetcher:)
    original = File.read(@lockfile)
    [original.sub("GEM\n  remote: https://rubygems.org/", "PATH\n  remote: ."),
      original.sub("GEM\n  remote: https://rubygems.org/", "GIT\n  remote: https://example.invalid/repo.git\n  revision: abc"),
      original.sub("https://rubygems.org/", "https://example.invalid/")].each do |contents|
      File.write(@lockfile, contents)
      manifest = JSON.parse(File.read(runner.run(gemfile: @gemfile)))
      expect(manifest.fetch("errors").join).to match(/unsupported.*(?:source|registry)/)
    end
  end
end
