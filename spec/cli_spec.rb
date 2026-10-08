# frozen_string_literal: true

require "bonebed/cli"
require "tmpdir"

RSpec.describe Bonebed::CLI do
  before { allow(Bonebed::Doctor).to receive(:container?).and_return(true) }

  it "prints the version for all version aliases" do
    %w[--version -v version].each do |flag|
      expect { expect(described_class.start([flag])).to eq(0) }.to output("#{Bonebed::VERSION}\n").to_stdout
    end
  end

  it "prints command-specific help without running commands" do
    %w[doctor baseline dig survey report migrate policy dataset monitor run static bundle].each do |command|
      expect { expect(described_class.start([command, "--help"])).to eq(0) }.to output(/Usage: bonebed #{command}/).to_stdout
    end
  end

  it "uses exit 64 for invalid options, commands, and arguments" do
    [["missing"], ["dig", "--invalid"], ["dig", "--gemfile", "Gemfile.lock", "--phase", "invalid"],
      ["dig", "--gemfile", "Gemfile.lock", "--version", "1.0"], ["doctor", "extra"], ["report"], ["survey", "--top", "0"]].each do |args|
      expect { expect(described_class.start(args)).to eq(64) }.to output(/.+/).to_stderr
    end
  end

  context "when digging a gem" do
    let(:dig) { double("dig", last_errors: [], last_observer_errors: []) }
    let(:manifest) do
      {"gem" => {"name" => "demo", "version" => "1.0.0"}, "phase" => "require",
       "stats" => {"wall_ms" => 500}, "network" => [], "exec" => [], "files" => {"notable" => []}}
    end

    around do |example|
      Dir.mktmpdir do |directory|
        @manifest_path = File.join(directory, "demo.json")
        File.write(@manifest_path, JSON.generate(manifest))
        example.run
      end
    end

    before do
      allow(Bonebed::Dig).to receive(:new).and_return(dig)
      allow(dig).to receive(:run).and_return(@manifest_path)
    end

    it "prints only the manifest path to stdout and a summary to stderr" do
      expect { expect(described_class.start(%w[dig demo])).to eq(0) }
        .to output("#{@manifest_path}\n").to_stdout
        .and output(/demo 1.0.0 \(require\).*0.5s.*network\s+none.*exec\s+none.*notable\s+none/m).to_stderr
    end

    it "forwards capture limits and lets Dig choose the phase timeout" do
      expect(Bonebed::Dig).to receive(:new).with(hash_including(timeout: nil, quiet_target: true, output_limit: 128, argv_limit: 4)).and_return(dig)
      expect { described_class.start(%w[dig demo --quiet-target --output-limit 128 --argv-limit 4]) }.to output.to_stdout.and output.to_stderr
    end

    it "forwards repeat counts and executable arguments without parsing target flags" do
      expect(Bonebed::Dig).to receive(:new).with(hash_including(repeat: 2)).and_return(dig)
      expect(dig).to receive(:run).with("demo", hash_including(phase: "exec", executable: "demo-tool", arguments: ["--version"]))
        .and_return(@manifest_path)
      expect { described_class.start(%w[dig demo --phase exec --executable demo-tool --repeat 2 -- --version]) }
        .to output.to_stdout.and output.to_stderr
    end

    it "summarizes nonempty observations as counts" do
      manifest["network"] = [{"family" => "inet", "addr" => "127.0.0.1", "port" => 443}]
      manifest["exec"] = [{"path" => "/usr/bin/echo"}]
      manifest["files"]["notable"] = ["$HOME/.aws/credentials"]
      File.write(@manifest_path, JSON.generate(manifest))
      expect { described_class.start(%w[dig demo]) }.to output.to_stdout.and output(/network\s+1.*exec\s+1.*notable\s+1/m).to_stderr
    end

    it "warns for observer failures and fails only in strict mode" do
      allow(dig).to receive(:last_observer_errors).and_return(["connect: decoder failure"])
      expect { expect(described_class.start(%w[dig demo])).to eq(0) }.to output.to_stdout.and output(/observer.*decoder failure/).to_stderr
      expect { expect(described_class.start(%w[dig demo --strict])).to eq(2) }.to output.to_stdout.and output.to_stderr
    end

    it "reports target failure before strict observer failure" do
      allow(dig).to receive(:last_errors).and_return(["exit status 1"])
      allow(dig).to receive(:last_observer_errors).and_return(["decoder failure"])
      expect { expect(described_class.start(%w[dig demo --strict])).to eq(1) }.to output.to_stdout.and output.to_stderr
    end

    it "warns when running target code on the host" do
      allow(Bonebed::Doctor).to receive(:container?).and_return(false)
      expect { described_class.start(%w[dig demo]) }.to output.to_stdout.and output(/host.*trusted/m).to_stderr
    end

    it "uses exit 1 for missing installed gems" do
      allow(dig).to receive(:run).and_raise(Gem::LoadError, "missing gem")
      expect { expect(described_class.start(%w[dig demo])).to eq(1) }.to output(/missing gem/).to_stderr
    end
  end

  it "honors strict mode for survey observer failures" do
    survey = double("survey", run: true, last_observer_errors: ["decoder failure"])
    allow(Bonebed::Dig).to receive(:new).and_return(double("dig"))
    allow(Bonebed::Survey).to receive(:new).and_return(survey)
    allow(Bonebed::Survey).to receive(:file).with("gems.txt").and_return([{name: "demo"}])
    expect { expect(described_class.start(%w[survey --file gems.txt --strict])).to eq(2) }.to output(/observer.*decoder failure/).to_stderr
  end
end
