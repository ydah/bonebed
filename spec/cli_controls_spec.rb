# frozen_string_literal: true

require "bonebed/cli"
require "bonebed/bundle_runner"

RSpec.describe "observation CLI controls" do
  around do |example|
    Dir.mktmpdir do |directory|
      Dir.chdir(directory) { example.run }
    end
  end

  let(:manifest) do
    {"schema_version" => 2, "gem" => {"name" => "demo", "version" => "1.0.0"}, "phase" => "require",
     "files" => {"read" => ["$HOME/.aws/credentials"], "write" => [], "notable" => ["$HOME/.aws/credentials"]},
     "network" => [], "exec" => [{"path" => "/usr/bin/tool"}], "stats" => {"wall_ms" => 50, "open_total" => 12},
     "target" => {"exit_status" => 0}, "observer_errors" => [], "stdout" => "secret output",
     "findings" => [{"severity" => "low", "capability" => "fake"}]}
  end

  before do
    File.write("manifest.json", JSON.generate(manifest))
    File.write("gems.txt", "demo\n")
    allow(Bonebed::Doctor).to receive(:container?).and_return(false)
  end

  it "rejects opted-in host execution before any target starts across observation commands" do
    expect(Bonebed::Session).not_to receive(:new)
    expect_any_instance_of(Bonebed::Dig).not_to receive(:run)
    expect_any_instance_of(Bonebed::BundleRunner).not_to receive(:run)
    expect_any_instance_of(Bonebed::CommandRunner).not_to receive(:run)
    [%w[dig demo], %w[survey --file gems.txt], %w[bundle], %w[monitor --file gems.txt], %w[compare demo 1 2]].each do |command|
      expect { expect(Bonebed::CLI.start(command + ["--require-container"])).to eq(2) }.to output(/container.*required/i).to_stderr
    end
    expect { expect(Bonebed::CLI.start(%w[run --require-container -- ruby -e exit])).to eq(2) }.to output(/container.*required/i).to_stderr
  end

  it "permits containers and explicit host overrides regardless of flag order" do
    dig = double(run: "manifest.json", last_errors: [], last_observer_errors: [])
    allow(Bonebed::Dig).to receive(:new).and_return(dig)
    [%w[--require-container --allow-host], %w[--allow-host --require-container]].each do |flags|
      expect { expect(Bonebed::CLI.start(["dig", "demo", *flags])).to eq(0) }.to output("manifest.json\n").to_stdout.and output(/host/).to_stderr
    end
    allow(Bonebed::Doctor).to receive(:container?).and_return(true)
    expect { expect(Bonebed::CLI.start(%w[dig demo --require-container])).to eq(0) }.to output("manifest.json\n").to_stdout.and output.to_stderr
  end

  it "loads the host guard from configuration and validates boolean defaults" do
    File.write(".bonebed.yml", "defaults:\n  require_container: true\n")
    expect { expect(Bonebed::CLI.start(%w[dig demo])).to eq(2) }.to output(/container.*required/i).to_stderr
    %w[verbose require_container allow_host].each do |key|
      expect { Bonebed::Policy.new("defaults" => {key => "true"}) }.to raise_error(ArgumentError, /boolean/)
    end
  end

  it "adds diagnostics only to stderr without forwarding CLI-only options to the runner" do
    allow(Bonebed::Doctor).to receive(:container?).and_return(true)
    expect(Bonebed::CommandRunner).to receive(:new).with(results_dir: "results", timeout: 60, offline: false, env_profile: "dev")
      .and_return(double(run: "manifest.json", last_errors: [], last_observer_errors: []))
    expect { expect(Bonebed::CLI.start(%w[run --verbose --require-container -- ruby --allow-host])).to eq(0) }
      .to output("manifest.json\n").to_stdout.and output(/Diagnostic:.*ruby=.*container=true.*open_total=12/m).to_stderr
  end

  it "forwards denial policies through both direct and survey gem observations" do
    dig = double(run: "manifest.json", last_errors: [], last_observer_errors: [])
    expect(Bonebed::Dig).to receive(:new).with(hash_including(deny: "rules.yml")).twice.and_return(dig)
    allow(Bonebed::Survey).to receive(:new).and_return(double(run: true, last_observer_errors: [], fatal_observer_error?: false, target_failed?: false))
    expect { expect(Bonebed::CLI.start(%w[dig demo --deny rules.yml])).to eq(0) }.to output.to_stdout.and output.to_stderr
    expect { expect(Bonebed::CLI.start(%w[survey --file gems.txt --deny rules.yml])).to eq(0) }.to output.to_stderr
  end

  it "uses configured top fallbacks with CLI overrides and rejects them for other survey sources" do
    allow(Bonebed::Doctor).to receive(:container?).and_return(true)
    File.write(".bonebed.yml", "defaults:\n  top_fallback: reviewed.txt\n")
    allow(Bonebed::Dig).to receive(:new).and_return(double)
    allow(Bonebed::Survey).to receive(:new).and_return(double(run: true, last_observer_errors: [], fatal_observer_error?: false, target_failed?: false))
    expect(Bonebed::Survey).to receive(:top).with(2, fallback: "reviewed.txt").and_return([{name: "rake"}, {name: "json"}])
    expect(Bonebed::CLI.start(%w[survey --top 2])).to eq(0)
    expect(Bonebed::Survey).to receive(:top).with(2, fallback: "newer.txt").and_return([{name: "rake"}, {name: "json"}])
    expect(Bonebed::CLI.start(%w[survey --top 2 --top-fallback newer.txt])).to eq(0)
    expect(Bonebed::CLI.start(%w[survey --file gems.txt])).to eq(0)
    expect { expect(Bonebed::CLI.start(%w[survey --file gems.txt --top-fallback reviewed.txt])).to eq(64) }
      .to output(/top-fallback requires --top/).to_stderr
    [true, ""].each do |value|
      expect { Bonebed::Policy.new("defaults" => {"top_fallback" => value}) }.to raise_error(ArgumentError, /top_fallback/)
    end
  end

  it "uses default policy severity instead of saved findings and omits diagnostics by default" do
    expect { Bonebed::CLI.summarize("manifest.json") }.to output(/severity\s+critical=1, medium=1/).to_stderr
    expect { Bonebed::CLI.summarize("manifest.json") }.not_to output(/Diagnostic:|secret output/).to_stderr
  end

  it "colors severity on terminals and honors redirected output and NO_COLOR" do
    previous = $stderr
    previous_no_color = ENV["NO_COLOR"]
    output = StringIO.new
    $stderr = output
    allow(output).to receive(:tty?).and_return(true)
    ENV.delete("NO_COLOR")
    Bonebed::CLI.summarize("manifest.json")
    expect(output.string).to include("\e[", "critical=1")
    [false, true].each do |terminal|
      output.truncate(0)
      output.rewind
      allow(output).to receive(:tty?).and_return(terminal)
      ENV["NO_COLOR"] = "1" if terminal
      Bonebed::CLI.summarize("manifest.json")
      expect(output.string).not_to include("\e[")
    end
  ensure
    $stderr = previous
    previous_no_color.nil? ? ENV.delete("NO_COLOR") : ENV["NO_COLOR"] = previous_no_color
  end
end
