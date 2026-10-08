# frozen_string_literal: true

require "bonebed/prefetcher"
require "tmpdir"
require "stringio"

RSpec.describe Bonebed::Prefetcher do
  around do |example|
    Dir.mktmpdir("bonebed-prefetch-spec-") do |root|
      @root = root
      @cache = File.join(root, "cache")
      example.run
    end
  end

  let(:prefetcher) { described_class.new(directory: @cache) }
  let(:set) { instance_double(Gem::RequestSet, resolve: nil, sorted_requests: requests) }
  let(:dependency) { resolver_spec("dependency") }
  let(:target) { resolver_spec("target") }
  let(:requests) { [double(spec: dependency), double(spec: target)] }

  before { allow(Gem::RequestSet).to receive(:new).and_return(set) }

  it "downloads verified archives in dependency order without executing gem code" do
    paths = prefetcher.call("target", "1.0.0")
    expect(paths.map { |path| Gem::Package.new(path).spec.name }).to eq(%w[dependency target])
    expect(paths).to all(match(%r{/\h{64}\.gem\z}))
    expect(File).not_to exist(File.join(@root, "executed"))
    expect(Gem::RequestSet).to have_received(:new).with(have_attributes(name: "target", requirement: Gem::Requirement.new("= 1.0.0")))
  end

  it "reuses archives only when their digest still matches" do
    paths = prefetcher.call("target")
    expect(prefetcher.call("target")).to eq(paths)
    expect(dependency).to have_received(:download).once
    File.write(paths.first, "damaged")
    expect(prefetcher.call("target")).to eq(paths)
    expect(Gem::Package.new(paths.first).spec.name).to eq("dependency")
    expect(dependency).to have_received(:download).twice
    expect(target).to have_received(:download).once
  end

  it "rejects downloaded archives that do not match the resolved gem" do
    allow(target).to receive(:download) do |install_dir:|
      path = File.join(install_dir, "wrong.gem")
      FileUtils.cp(@archives.fetch("dependency"), path)
      path
    end
    expect { prefetcher.call("target") }.to raise_error(described_class::Error, /prefetch_failed:.*identity/)
    expect(Dir[File.join(@cache, "*.gem")].size).to eq(1)
  end

  it "classifies download failures and removes partial files" do
    allow(dependency).to receive(:download) do |install_dir:|
      File.write(File.join(install_dir, "partial.gem"), "partial")
      raise IOError, "download interrupted"
    end
    expect { prefetcher.call("target") }.to raise_error(described_class::Error, /prefetch_failed:.*download interrupted/)
    expect(Dir.children(@cache)).to be_empty
  end

  it "classifies resolution failures and restores the process platform" do
    original_platforms = Gem.platforms
    allow(set).to receive(:resolve) do
      expect(Gem.platforms).to eq([Gem::Platform::RUBY])
      raise Gem::DependencyError, "unavailable gem"
    end
    expect { prefetcher.call("target", platform: "ruby") }.to raise_error(described_class::Error, /prefetch_failed:.*unavailable gem/)
    expect(Gem.platforms).to equal(original_platforms)
  end

  def resolver_spec(name)
    @archives ||= {}
    archive_dir = File.join(@root, name)
    FileUtils.mkdir_p(archive_dir)
    specification = Gem::Specification.new do |spec|
      spec.name = name
      spec.version = "1.0.0"
      spec.authors = ["Bonebed"]
      spec.summary = "Prefetch fixture"
      spec.license = "MIT"
      spec.homepage = "https://example.invalid"
      spec.files = ["ext/extconf.rb"]
      spec.extensions = ["ext/extconf.rb"]
    end
    Dir.chdir(archive_dir) do
      FileUtils.mkdir_p("ext")
      File.write("ext/extconf.rb", "File.write(#{File.join(@root, "executed").inspect}, 'executed')")
      Gem::DefaultUserInteraction.use_ui(Gem::SilentUI.new) { Gem::Package.build(specification) }
    end
    @archives[name] = File.join(archive_dir, specification.file_name)
    resolver = double("resolver spec", spec: specification, source: double(uri: URI("https://example.invalid")))
    allow(resolver).to receive(:download) do |install_dir:|
      path = File.join(install_dir, specification.file_name)
      FileUtils.cp(@archives.fetch(name), path)
      path
    end
    resolver
  end
end
