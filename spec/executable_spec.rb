# frozen_string_literal: true

require "bonebed/phase/executable"
require "rubygems/package"

RSpec.describe Bonebed::Phase::Executable do
  it "requires an unambiguous declared executable and rejects paths" do
    spec = Gem::Specification.new
    expect { described_class.select(spec) }.to raise_error(ArgumentError, /no executable/)
    spec.executables = %w[first second]
    expect { described_class.select(spec) }.to raise_error(ArgumentError, /--executable/)
    expect(described_class.select(spec, "second")).to eq("second")
    expect { described_class.select(spec, "missing") }.to raise_error(ArgumentError, /not declared/)
    spec.executables = ["../escape"]
    expect { described_class.select(spec) }.to raise_error(ArgumentError, /invalid executable/)
  end

  it "installs and runs the selected gem wrapper with literal arguments and caches its exact invocation" do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")

    Dir.mktmpdir do |root|
      FileUtils.mkdir_p(File.join(root, "bin"))
      File.write(File.join(root, "bin", "bonebed-executable-probe"), <<~RUBY)
        #!/usr/bin/env ruby
        require "json"
        File.write("executable-ran", "yes")
        puts JSON.generate(ARGV)
      RUBY
      spec = Gem::Specification.new do |item|
        item.name = "bonebed-executable-probe"
        item.version = "1.0.0"
        item.summary = "Fixture"
        item.authors = ["Bonebed"]
        item.files = ["bin/bonebed-executable-probe"]
        item.executables = ["bonebed-executable-probe"]
      end
      package = Dir.chdir(root) { Gem::Package.build(spec) }
      probe = Bonebed::Dig.new
      baseline = Bonebed::Baseline::Result.new(id: "test", observation: probe.send(:empty_observation))
      dig = Bonebed::Dig.new(results_dir: File.join(root, "results"), quiet_target: true,
        baseline: double("baseline", capture: baseline), prefetcher: double("prefetcher", call: [File.join(root, package)]))
      arguments = ["a b", "$(echo literal)", ";"]
      path = dig.run(spec.name, phase: "exec", arguments:)
      manifest = JSON.parse(File.read(path))
      expect(manifest.fetch("errors")).to be_empty
      expect(manifest.fetch("phase")).to eq("exec")
      expect(JSON.parse(manifest.fetch("stdout"))).to eq(arguments)
      expect(manifest.fetch("command")).to include("$GEM_HOME/bin/bonebed-executable-probe")
      expect(manifest.dig("files", "write")).to include("$PWD/executable-ran")
      expect(dig.result_exists?(spec.name, phase: "exec", arguments:)).to be(true)
      expect(dig.result_exists?(spec.name, phase: "exec", executable: "other", arguments:)).to be(false)
      expect(dig.result_exists?(spec.name, phase: "exec", arguments: ["different"])).to be(false)
      expect(Bonebed::ResultStore.read(File.join(root, "results")).map { |result| result.fetch("phase") }.sort).to eq(%w[exec install])
      manifest["gem"]["executables"] << "another"
      Bonebed::ResultStore.new(File.join(root, "results")).write(manifest)
      expect(dig.result_exists?(spec.name, phase: "exec", arguments:)).to be(false)
      expect(dig.result_exists?(spec.name, phase: "exec", executable: spec.executables.first, arguments:)).to be(true)
    end
  end
end
