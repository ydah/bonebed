# frozen_string_literal: true

require "bonebed/bundler_plugin"
require "open3"
require "rubygems/package"

RSpec.describe Bonebed::BundlerPlugin do
  around do |example|
    Dir.mktmpdir("bonebed-plugin-") do |root|
      @root = root
      @results = File.join(root, "results")
      @lock = File.join(root, "Gemfile.lock")
      @approval = File.join(root, "Gemfile.capabilities.lock")
      FileUtils.mkdir_p(@results)
      File.write(File.join(root, "Gemfile"), "source 'https://rubygems.org'\ngem 'demo', '= 1.0'\n")
      File.write(@lock, <<~LOCK)
        GEM
          remote: https://rubygems.org/
          specs:
            demo (1.0)

        PLATFORMS
          ruby

        DEPENDENCIES
          demo (= 1.0)

        BUNDLED WITH
           #{Bundler::VERSION}
      LOCK
      @approvals = {"version" => 1, "gems" => {"demo" => {"version" => "1.0", "phases" => {"install" => [], "require" => []}}}}
      write_approvals
      %w[install require].each { |phase| save(phase) }
      example.run
    end
  end

  def write_approvals
    File.write(@approval, YAML.dump(@approvals))
  end

  def save(phase, **changes)
    data = {"schema_version" => 2, "gem" => {"name" => "demo", "version" => "1.0", "platform" => "ruby", "rubygems_plugin" => false},
            "phase" => phase, "files" => {"read" => {"self" => [], "resolver" => [], "other" => []}, "write" => []},
            "network" => [], "exec" => [], "threads" => [], "errors" => [], "observer_errors" => [],
            "run" => {"mode" => {"writes_only" => false}}, "target" => {"exit_status" => 0, "signal" => nil, "timed_out" => false}}
    File.write(File.join(@results, "#{phase}.json"), JSON.generate(data.merge(changes.transform_keys(&:to_s))))
  end

  def gate
    described_class.new(lockfile: @lock, results_dir: @results, approval_path: @approval)
  end

  it "accepts complete approved observations without evaluating the Gemfile" do
    marker = File.join(@root, "gemfile-ran")
    File.write(File.join(@root, "Gemfile"), "File.write(#{marker.inspect}, 'no')")
    expect(gate.check!).to eq(1)
    expect(File).not_to exist(marker)
  end

  it "refuses absent, malformed, and stale approvals even for gems with no capabilities" do
    @approvals["gems"].clear
    write_approvals
    expect { gate.check! }.to raise_error(described_class::Rejected, /approval.*demo/)
    @approvals["gems"]["demo"] = {"version" => "0.9", "phases" => {"install" => [], "require" => []}}
    write_approvals
    expect { gate.check! }.to raise_error(described_class::Rejected, /version/)
    File.write(@approval, "--- !ruby/object:Object {}")
    expect { gate.check! }.to raise_error(described_class::Rejected, /YAML/)
    File.unlink(@approval)
    expect { gate.check! }.to raise_error(described_class::Rejected, /No such file/)
  end

  it "refuses missing phases and incompatible package observations" do
    File.unlink(File.join(@results, "require.json"))
    expect { gate.check! }.to raise_error(described_class::Rejected, /require.*unobserved/)
    save("require", gem: {"name" => "demo", "version" => "2.0", "platform" => "ruby"})
    expect { gate.check! }.to raise_error(described_class::Rejected, /require.*unobserved/)
    save("require", gem: {"name" => "demo", "version" => "1.0", "platform" => "x86_64-other"})
    expect { gate.check! }.to raise_error(described_class::Rejected, /require.*unobserved/)
  end

  it "rejects target errors, observer gaps, unknown statuses, and partial repeat groups" do
    [{errors: ["failed"]}, {observer_errors: ["lost event"]}, {target: {"exit_status" => nil}},
      {run: {"mode" => {"writes_only" => true}}},
      {:run => {"mode" => {"writes_only" => false, "repeat" => 2}, "repeat" => {"group" => "test", "index" => 1, "count" => 2}}, "stability" => {"complete" => false}}].each do |changes|
      save("require", **changes)
      expect { gate.check! }.to raise_error(described_class::Rejected, /incomplete/)
    end
  end

  it "rejects a repeated mode without sample metadata" do
    save("require", run: {"mode" => {"writes_only" => false, "repeat" => 3}})
    expect { gate.check! }.to raise_error(described_class::Rejected, /incomplete/)
  end

  it "rejects sample counts that disagree with the observation mode" do
    save("require", run: {"mode" => {"writes_only" => false, "repeat" => 1},
                          "repeat" => {"group" => "partial", "index" => 1, "count" => 3}}, stability: {"complete" => true, "samples" => 3})
    expect { gate.check! }.to raise_error(described_class::Rejected, /incomplete/)
  end

  it "accepts a full repeat group and rejects missing or miscounted samples" do
    3.times do |index|
      save("require", run: {"mode" => {"writes_only" => false, "repeat" => 3},
                            "repeat" => {"group" => "complete", "index" => index + 1, "count" => 3}}, stability: {"complete" => true, "samples" => 3})
      File.rename(File.join(@results, "require.json"), File.join(@results, "repeat#{index}.json"))
    end
    expect(gate.check!).to eq(1)
    path = File.join(@results, "repeat2.json")
    sample = JSON.parse(File.read(path))
    sample["stability"]["samples"] = 1
    File.write(path, JSON.generate(sample))
    expect { gate.check! }.to raise_error(described_class::Rejected, /incomplete/)
    File.unlink(path)
    expect { gate.check! }.to raise_error(described_class::Rejected, /incomplete/)
  end

  it "rejects malformed JSON alongside otherwise complete observations" do
    File.write(File.join(@results, "corrupt.json"), "not JSON")
    expect { gate.check! }.to raise_error(described_class::Rejected, /invalid observation.*corrupt/)
  end

  it "rejects structurally invalid duplicates before selecting successful observations" do
    invalid = JSON.parse(File.read(File.join(@results, "require.json")))
    invalid["files"]["read"] = "not a read group"
    File.write(File.join(@results, "invalid.json"), JSON.generate(invalid))
    expect { gate.check! }.to raise_error(described_class::Rejected, /invalid observation.*invalid/)
  end

  it "requires declared plugin observations and rejects keys outside approval or policy" do
    save("install", gem: {"name" => "demo", "version" => "1.0", "platform" => "ruby", "rubygems_plugin" => true})
    expect { gate.check! }.to raise_error(described_class::Rejected, /plugin/)
    save("install")
    save("require", files: {"read" => {"self" => [], "resolver" => [], "other" => []}, "write" => ["$PWD/new"]})
    expect { gate.check! }.to raise_error(described_class::Rejected, /unapproved.*file:write/)
    save("require", files: {"read" => {"self" => [], "resolver" => [], "other" => ["$HOME/.ssh/id_rsa"]}, "write" => []})
    @approvals["gems"]["demo"]["phases"]["require"] = ["file:read:$HOME/.ssh/id_rsa"]
    write_approvals
    expect { gate.check! }.to raise_error(described_class::Rejected, /policy/)
  end

  it "rejects path, git, and alternative registry sources" do
    original = File.read(@lock)
    [original.sub("GEM\n  remote: https://rubygems.org/", "PATH\n  remote: ."),
      original.sub("GEM\n  remote: https://rubygems.org/", "GIT\n  remote: https://example.invalid/repo\n  revision: abc"),
      original.sub("https://rubygems.org/", "https://example.invalid/")].each do |contents|
      File.write(@lock, contents)
      expect { gate.check! }.to raise_error(described_class::Rejected, /unsupported/)
    end
  end

  it "rejects source-plugin sections before Bundler can load source-plugin code" do
    File.write(@lock, "PLUGIN SOURCE\n  remote: https://example.invalid\n  type: arbitrary\n  specs:\n    demo (1.0)\n")
    expect(Bundler::Plugin).not_to receive(:from_lock)
    expect { gate.check! }.to raise_error(described_class::Rejected, /unsupported source/)
  end

  it "checks the actual install identity against the preflight snapshot" do
    checker = gate
    checker.check!
    spec = Gem::Specification.new { |item|
      item.name = "demo"
      item.version = "1.0"
    }
    spec.source = Bundler::Source::Rubygems.new("remotes" => ["https://rubygems.org/"])
    expect(checker.check_spec!(spec)).to be(true)
    spec.version = "2.0"
    expect { checker.check_spec!(spec) }.to raise_error(described_class::Rejected, /not approved/)
  end

  def install_with_hook(frozen: true)
    source = File.expand_path("..", __dir__)
    program = <<~RUBY
      installation_path = ENV.delete("BUNDLE_PATH")
      require "bundler"
      require "bundler/cli"
      require "rubygems/installer"
      Gem::Installer.at(#{Gem.loaded_specs.fetch("seccomp-notify").cache_file.inspect},
        install_dir: Bundler::Plugin.root.to_s, document: []).install
      Bundler::Plugin.install(["bonebed"], path: #{source.inspect})
      raise "observer loaded in Bundler" if $LOADED_FEATURES.any? { |path| path.include?("seccomp") }
      ENV["BUNDLE_PATH"] = installation_path
      Bundler.reset!
      Bundler::CLI.start(["install", "--local"])
    RUBY
    environment = {"HOME" => @root, "PATH" => ENV.fetch("PATH"), "BUNDLE_USER_HOME" => File.join(@root, "user-bundle"),
                   "BUNDLE_APP_CONFIG" => File.join(@root, ".bundle"), "BUNDLE_GEMFILE" => File.join(@root, "Gemfile"),
                   "BUNDLE_PATH" => File.join(@root, "installed"), "BUNDLE_FROZEN" => frozen.to_s, "BUNDLE_PLUGINS" => "true",
                   "BUNDLE_SILENCE_ROOT_WARNING" => "true", "BUNDLE_DISABLE_VERSION_CHECK" => "true"}
    Open3.capture3(environment, RbConfig.ruby, "-e", program, chdir: @root, unsetenv_others: true)
  end

  def cache_fixture
    FileUtils.mkdir_p(File.join(@root, "vendor/cache"))
    File.write(File.join(@root, "fixture.txt"), "fixture")
    specification = Gem::Specification.new do |item|
      item.name = "demo"
      item.version = "1.0"
      item.summary = "Bundler plugin fixture"
      item.authors = ["Bonebed"]
      item.license = "MIT"
      item.homepage = "https://example.invalid"
      item.required_ruby_version = ">= 3.2"
      item.files = ["fixture.txt"]
    end
    Dir.chdir(@root) { Gem::Package.build(specification, false, false, "vendor/cache/demo-1.0.gem") }
  end

  it "runs the registered Bundler hooks during a real local install in an isolated subprocess" do
    cache_fixture
    stdout, stderr, status = install_with_hook
    expect(status.success?).to be(true), "#{stdout}\n#{stderr}"
    expect(stdout).to include("Bonebed approved 1")
    expect(Dir[File.join(@root, "installed/**/specifications/demo-1.0.gemspec")]).not_to be_empty
  end

  it "aborts the real installer before writing a gem when approval or frozen mode is missing" do
    cache_fixture
    stdout, stderr, status = install_with_hook(frozen: false)
    expect(status.success?).to be(false), stdout
    expect(stderr).to include("BUNDLE_FROZEN=true")
    File.unlink(@approval)
    stdout, stderr, status = install_with_hook
    expect(status.success?).to be(false), stdout
    expect(stderr).to include("Bonebed check failed")
    expect(Dir[File.join(@root, "installed/**/specifications/demo-1.0.gemspec")]).to be_empty
  end
end
