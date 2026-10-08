# frozen_string_literal: true

require "bonebed/gem_environment"

RSpec.describe Bonebed::GemEnvironment do
  it "creates a disposable environment and cleans it after exceptions" do
    root = nil
    expect do
      described_class.open do |environment|
        root = environment.root
        expect([environment.gem_home, environment.home, environment.project, environment.tmpdir, environment.prefetch]).to all(satisfy { |path| Dir.exist?(path) })
        expect(environment.env).to include("HOME" => environment.home, "GEM_HOME" => environment.gem_home,
          "GEM_PATH" => environment.gem_home, "TMPDIR" => environment.tmpdir)
        expect(environment.env).not_to have_key("BUNDLE_GEMFILE")
        expect(environment.normalizer.call(File.join(environment.home, ".aws/credentials"))).to eq("$HOME/.aws/credentials")
        expect(environment.normalizer.call(File.join(environment.project, ".env"))).to eq("$PWD/.env")
        expect(File.read(File.join(environment.home, ".aws/credentials"))).to include("AKIA")
        raise "fixture failure"
      end
    end.to raise_error("fixture failure")
    expect(File.exist?(root)).to be(false)
  end

  it "never writes honeypot files into explicit home or project overrides" do
    Dir.mktmpdir do |project|
      allow(Dir).to receive(:home).and_return(project)
      described_class.open(real_home: true, cwd: project) do |environment|
        expect(environment.home).to eq(project)
        expect(environment.project).to eq(project)
        expect(Dir.children(project)).to be_empty
      end
      expect(Dir.exist?(project)).to be(true)
    end
  end

  it "copies gem files, gemspecs and extensions without writable host links" do
    Dir.mktmpdir do |source|
      gem_dir = File.join(source, "gems", "demo-1.0")
      extension_dir = File.join(source, "extensions", "platform", "version", "demo-1.0")
      specification_path = File.join(source, "specifications", "demo-1.0.gemspec")
      FileUtils.mkdir_p([gem_dir, extension_dir, File.dirname(specification_path)])
      File.write(File.join(gem_dir, "demo.rb"), "original")
      File.symlink("demo.rb", File.join(gem_dir, "alias.rb"))
      File.write(File.join(extension_dir, "demo.so"), "extension")
      File.write(specification_path, "specification")
      specification = double("specification", full_name: "demo-1.0", full_gem_path: gem_dir,
        loaded_from: specification_path, extension_dir:, base_dir: source)

      described_class.open(honeypot: false) do |environment|
        environment.copy_specification(specification)
        copy = File.join(environment.gem_home, "gems", "demo-1.0", "alias.rb")
        File.write(copy, "changed")
        expect(File.symlink?(copy)).to be(false)
        expect(File.read(File.join(gem_dir, "demo.rb"))).to eq("original")
        expect(File.read(File.join(environment.gem_home, "extensions", "platform", "version", "demo-1.0", "demo.so"))).to eq("extension")
        expect(File.read(File.join(environment.gem_home, "specifications", "demo-1.0.gemspec"))).to eq("specification")
      end
    end
  end

  it "rejects gem symlinks escaping their source tree" do
    Dir.mktmpdir do |source|
      gem_dir = File.join(source, "gem")
      FileUtils.mkdir_p(gem_dir)
      File.write(File.join(source, "secret"), "private")
      File.symlink("../secret", File.join(gem_dir, "escape"))
      specification = double("specification", full_name: "demo-1.0", full_gem_path: gem_dir)
      described_class.open(honeypot: false) do |environment|
        expect { environment.copy_specification(specification) }.to raise_error(ArgumentError, /outside/)
      end
    end
  end

  it "rejects cyclic links without recursive copying" do
    Dir.mktmpdir do |source|
      File.symlink(".", File.join(source, "cycle"))
      specification = double("specification", full_name: "demo-1.0", full_gem_path: source)
      described_class.open(honeypot: false) do |environment|
        expect { environment.copy_specification(specification) }.to raise_error(ArgumentError, /cyclic/)
      end
    end
  end
end
