# frozen_string_literal: true

require "bonebed/cli"
require "bonebed/analysis_cli"
require "tmpdir"

RSpec.describe "analysis commands" do
  around do |example|
    Dir.mktmpdir("bonebed-analysis-") { |root| Dir.chdir(root) { example.run } }
  end

  before { allow(Bonebed::Doctor).to receive(:container?).and_return(true) }

  let(:before_manifest) { manifest("demo", "1.0.0") }
  let(:after_manifest) { manifest("demo", "2.0.0", writes: ["$PWD/.git/hooks/pre-commit"]) }

  it "prints a file diff without observing anything" do
    File.write("before.json", JSON.generate(before_manifest))
    File.write("after.json", JSON.generate(after_manifest))
    expect(Bonebed::Dig).not_to receive(:new)
    expect { expect(Bonebed::CLI.diff(%w[before.json after.json --format json])).to eq(0) }
      .to output(/file:write:\$PWD\/\.git\/hooks\/pre-commit/).to_stdout
  end

  it "checks policy thresholds and defaults from the current policy file" do
    File.write("after.json", JSON.generate(after_manifest))
    expect { expect(Bonebed::CLI.check(%w[after.json --format json])).to eq(3) }.to output(/git-hook-write/).to_stdout
    File.write(".bonebed.yml", {"allow" => {"demo" => {"install" => ["file:write:$PWD/.git/hooks/**"]}}}.to_yaml)
    expect { expect(Bonebed::CLI.check(%w[after.json --format json])).to eq(0) }.to output.to_stdout
  end

  it "reuses successful observations when comparing versions" do
    store = Bonebed::ResultStore.new("results")
    store.write(before_manifest)
    store.write(after_manifest)
    expect_any_instance_of(Bonebed::Dig).not_to receive(:run)
    expect { expect(Bonebed::CLI.compare(%w[demo 1.0.0 2.0.0 --phase install --format json])).to eq(0) }
      .to output(/file:write:\$PWD\/\.git\/hooks\/pre-commit/).to_stdout
  end

  it "writes a capability lock and preserves other gems on a targeted update" do
    allow(Bonebed::Survey).to receive(:lockfile).with("Gemfile.lock").and_return([{name: "demo", version: "1.0.0"}, {name: "other", version: "1.0.0"}])
    store = Bonebed::ResultStore.new("results")
    store.write(before_manifest)
    store.write(manifest("other", "1.0.0"))
    expect { expect(Bonebed::CLI.lock(%w[--phase install])).to eq(0) }.to output(/Gemfile.capabilities.lock/).to_stdout
    initial = Bonebed::Policy.read_yaml("Gemfile.capabilities.lock")
    allow(Bonebed::Survey).to receive(:lockfile).with("Gemfile.lock").and_return([{name: "demo", version: "2.0.0"}, {name: "other", version: "2.0.0"}])
    store.write(after_manifest)
    expect { Bonebed::CLI.lock(%w[--phase install --update demo]) }.to output.to_stdout
    updated = Bonebed::Policy.read_yaml("Gemfile.capabilities.lock")
    expect(updated["gems"]["other"]).to eq(initial["gems"]["other"])
    expect(updated["gems"]["demo"]["version"]).to eq("2.0.0")
    File.write("after.json", JSON.generate(after_manifest.merge("exec" => [{"path" => "/usr/bin/new-tool"}])))
    expect { expect(Bonebed::CLI.check(%w[after.json --lock --format json])).to eq(3) }.to output(/capability-added/).to_stdout
  end

  it "observes only added or changed gems in lockfile differences" do
    allow(Bonebed::Survey).to receive(:lockfile).with("base.lock").and_return([{name: "demo", version: "1.0.0"}, {name: "same", version: "1.0.0"}])
    allow(Bonebed::Survey).to receive(:lockfile).with("head.lock").and_return([{name: "demo", version: "2.0.0"}, {name: "same", version: "1.0.0"}])
    File.write("before.json", JSON.generate(before_manifest))
    File.write("after.json", JSON.generate(after_manifest))
    dig = double("dig", observation_mode: before_manifest.fetch("run").fetch("mode"))
    allow(Bonebed::Dig).to receive(:new).and_return(dig)
    expect(dig).to receive(:run).with("demo", phase: "install", version: "1.0.0").and_return("before.json")
    expect(dig).to receive(:run).with("demo", phase: "install", version: "2.0.0").and_return("after.json")
    expect { expect(Bonebed::CLI.diff_lock(%w[base.lock head.lock --phase install --format json])).to eq(0) }.to output(/demo/).to_stdout
  end

  it "unions approval samples and rejects observations for a different version" do
    allow(Bonebed::Survey).to receive(:lockfile).and_return([{name: "demo", version: "1.0.0"}])
    first = manifest("demo", "1.0.0", writes: ["$PWD/a"])
    second = manifest("demo", "1.0.0", writes: ["$PWD/b"])
    allow(Bonebed::CLI).to receive(:observe_cached).and_return([first, second])
    expect { Bonebed::CLI.lock([]) }.to output.to_stdout
    approved = Bonebed::Policy.read_yaml("Gemfile.capabilities.lock")
    expect(approved.dig("gems", "demo", "phases", "install")).to contain_exactly("file:write:$PWD/a", "file:write:$PWD/b")
    allow(Bonebed::CLI).to receive(:observe_cached).and_return([first, after_manifest])
    expect { Bonebed::CLI.lock([]) }.to raise_error(ArgumentError, /version/)
    expect(Bonebed::Policy.read_yaml("Gemfile.capabilities.lock")).to eq(approved)
  end

  it "does not reuse a different executable invocation for an automatic exec phase" do
    observed = before_manifest.merge("phase" => "exec", "gem" => before_manifest["gem"].merge("executables" => ["demo"]),
      "run" => before_manifest["run"].merge("executable" => "demo", "arguments" => ["--unsafe"]))
    Bonebed::ResultStore.new("results").write(observed)
    File.write("observed.json", JSON.generate(observed))
    dig = double("dig", observation_mode: before_manifest.dig("run", "mode"))
    allow(Bonebed::Dig).to receive(:new).and_return(dig)
    expect(dig).to receive(:run).with("demo", phase: "exec", version: "1.0.0").and_return("observed.json")
    Bonebed::CLI.observe_cached("demo", "1.0.0", Bonebed::CLI.observation_defaults.merge(phase: "exec"))
  end

  it "rejects malformed locks and does not overwrite approvals on target failure" do
    File.write("bad.lock", "version: 1\ngems: []\n")
    File.write("before.json", JSON.generate(before_manifest))
    expect { Bonebed::CLI.check(%w[before.json --lock bad.lock]) }.to raise_error(ArgumentError)
    File.write("Gemfile.capabilities.lock", "existing approvals")
    allow(Bonebed::Survey).to receive(:lockfile).and_return([{name: "demo", version: "1.0.0"}])
    failed = before_manifest.merge("errors" => ["target failed"])
    File.write("failed.json", JSON.generate(failed))
    allow(Bonebed::Dig).to receive(:new).and_return(double(run: "failed.json", observation_mode: before_manifest.fetch("run").fetch("mode")))
    expect { expect(Bonebed::CLI.lock(%w[--phase install])).to eq(1) }.to output(/target failed/).to_stderr
    expect(File.read("Gemfile.capabilities.lock")).to eq("existing approvals")
  end

  it "requires a matching observation mode and a plugin observation for all phases" do
    store = Bonebed::ResultStore.new("results")
    installed = before_manifest.merge("gem" => before_manifest["gem"].merge("rubygems_plugin" => true))
    store.write(installed)
    store.write(installed.merge("phase" => "require"))
    File.write("observed.json", JSON.generate(installed))
    dig = double("dig", observation_mode: before_manifest.fetch("run").fetch("mode"))
    allow(Bonebed::Dig).to receive(:new).and_return(dig)
    expect(dig).to receive(:run).with("demo", phase: "all", version: "1.0.0").and_return(["observed.json"])
    Bonebed::CLI.observe_cached("demo", "1.0.0", Bonebed::CLI.observation_defaults)
    allow(dig).to receive(:observation_mode).and_return(before_manifest.dig("run", "mode").merge("env_profile" => "prod"))
    expect(dig).to receive(:run).with("demo", phase: "install", version: "1.0.0").and_return("observed.json")
    Bonebed::CLI.observe_cached("demo", "1.0.0", Bonebed::CLI.observation_defaults.merge(phase: "install"))
  end

  it "rejects invalid formats before observing target code" do
    expect(Bonebed::Dig).not_to receive(:new)
    expect { Bonebed::CLI.compare(%w[demo 1.0 2.0 --format invalid]) }.to raise_error(OptionParser::InvalidArgument)
  end

  it "compares recent versions from a validated registry response" do
    store = Bonebed::ResultStore.new("results")
    store.write(before_manifest)
    store.write(after_manifest)
    response = Net::HTTPOK.new("1.1", "200", "OK")
    allow(response).to receive(:body).and_return(JSON.generate([{number: "2.0.0"}, {number: "1.0.0"}]))
    allow(Net::HTTP).to receive(:start).and_return(response)
    expect { expect(Bonebed::CLI.history(%w[demo --last 2 --phase install --format json])).to eq(0) }.to output(/pre-commit/).to_stdout
    allow(response).to receive(:body).and_return('{"number":"invalid"}')
    expect { Bonebed::CLI.history(%w[demo --last 2 --phase install]) }.to raise_error(Bonebed::Error, /versions response/)
  end

  it "formats JSON, CSV, HTML, and SARIF without injecting HTML or spreadsheet formulas" do
    input = after_manifest.merge("gem" => {"name" => "=bad<script>", "version" => "1.0.0"})
    expect(JSON.parse(Bonebed::CLI.format_report([input], "json"))).to eq([input])
    expect(Bonebed::CLI.format_report([input], "html")).to include("&lt;script&gt;")
    expect(Bonebed::CLI.format_report([input], "csv")).to include("'=bad<script>")
    expect(JSON.parse(Bonebed::CLI.format_report([input], "sarif"))["version"]).to eq("2.1.0")
  end

  def manifest(name, version, writes: [])
    {"schema_version" => 2, "gem" => {"name" => name, "version" => version, "platform" => "ruby"}, "phase" => "install",
     "run" => {"mode" => {"offline" => false, "honeypot" => true, "env_profile" => "dev", "writes_only" => false, "real_home" => false, "cwd" => nil, "enforce" => nil}},
     "files" => {"read" => {"self" => [], "resolver" => [], "other" => []}, "write" => writes},
     "network" => [], "exec" => [], "threads" => [], "errors" => [], "observer_errors" => [], "target" => {"exit_status" => 0}}
  end
end
