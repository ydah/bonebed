# frozen_string_literal: true

require "bonebed/monitor"

RSpec.describe Bonebed::Monitor do
  def fake_dig(directory, failures = [])
    dig = double(last_errors: [], last_observer_errors: [], observation_mode: {}, result_exists?: true)
    allow(dig).to receive(:run) do |name, phase:, version:|
      expect(phase).to eq("all")
      failed = failures.include?(version)
      allow(dig).to receive(:last_errors).and_return(failed ? ["target failed"] : [])
      %w[install require].map do |observed_phase|
        path = File.join(directory, "#{name}-#{version}-#{observed_phase}.json")
        data = {"schema_version" => 1, "gem" => {"name" => name, "version" => version}, "phase" => observed_phase,
                "run" => {"mode" => dig.observation_mode},
                "files" => {"read" => [], "write" => []}, "network" => [], "exec" => [], "threads" => [],
                "errors" => failed ? ["target failed"] : [], "stats" => {}}
        File.write(path, JSON.generate(data))
        path
      end
    end
    dig
  end

  def with_monitor(registry, failures: [])
    Dir.mktmpdir do |directory|
      state = File.join(directory, "state.json")
      dig = fake_dig(directory, failures)
      monitor = described_class.new(results_dir: directory, state_path: state, dig:, registry:)
      yield monitor, dig, state, directory
    end
  end

  it "starts at the newest release and skips successful observations on the next run" do
    registry = ->(_) { [{"number" => "1.9"}, {"number" => "1.10"}] }
    with_monitor(registry) do |monitor, dig, state, directory|
      first = monitor.run(["demo"])
      expect(first.fetch(:observed).map { |entry| entry.fetch(:version) }).to eq(["1.10"])
      expect(monitor.run(["demo"]).fetch(:observed)).to be_empty
      expect(dig).to have_received(:run).once
      expect(JSON.parse(File.read(state)).dig("gems", "demo").values.first.fetch("observed")).to eq(["1.10"])
      expect(File.exist?(File.join(directory, "dataset", "changes.json"))).to be(true)
    end
  end

  it "retries a failed intermediate version even after a newer one succeeds" do
    failures = ["2"]
    registry = ->(_) { [{"number" => "1"}, {"number" => "2"}, {"number" => "3"}] }
    with_monitor(registry, failures:) do |monitor, dig, state, _|
      dig.run("demo", phase: "all", version: "1")
      expect(monitor.run(["demo"]).fetch(:errors).map { |entry| entry.fetch(:version) }).to eq(["2"])
      expect(JSON.parse(File.read(state)).dig("gems", "demo").values.first.fetch("observed")).to eq(["1", "3"])
      failures.clear
      expect(monitor.run(["demo"]).fetch(:observed).map { |entry| entry.fetch(:version) }).to eq(["2"])
      expect(dig).to have_received(:run).with("demo", phase: "all", version: "2").twice
    end
  end

  it "ignores yanked and prerelease versions without removing historical state" do
    versions = [{"number" => "1"}]
    with_monitor(->(_) { versions }) do |monitor, _, state, _|
      monitor.run(["demo"])
      before = File.read(state)
      versions.replace([{"number" => "2", "yanked" => true}, {"number" => "3.pre", "prerelease" => true}])
      expect(monitor.run(["demo"]).fetch(:observed)).to be_empty
      expect(File.read(state)).to eq(before)
    end
  end

  it "preserves state when the registry response is malformed or a target fails" do
    versions = [{"number" => "1"}]
    with_monitor(->(_) { versions }) do |monitor, _, state, _|
      monitor.run(["demo"])
      before = File.read(state)
      versions.replace([{"number" => "../../invalid"}])
      expect(monitor.run(["demo"]).fetch(:errors).first.fetch(:error)).to include("registry")
      expect(File.read(state)).to eq(before)
    end
    with_monitor(->(_) { [{"number" => "1"}] }, failures: ["1"]) do |monitor, _, state, _|
      expect(monitor.run(["demo"]).fetch(:errors).size).to eq(1)
      expect(File.exist?(state)).to be(false)
    end
  end

  it "retries an initial failed manifest when another release appears before the first success" do
    versions = [{"number" => "1"}]
    failures = ["1"]
    with_monitor(->(_) { versions }, failures:) do |monitor, _, _, _|
      monitor.run(["demo"])
      versions << {"number" => "2"}
      failures.clear
      expect(monitor.run(["demo"]).fetch(:observed).map { |entry| entry.fetch(:version) }).to eq(%w[1 2])
    end
  end

  it "keeps checkpoints separate when observation settings change" do
    registry = ->(_) { [{"number" => "1"}] }
    with_monitor(registry) do |monitor, dig, state, directory|
      monitor.run(["demo"])
      allow(dig).to receive(:observation_mode).and_return({"offline" => true})
      changed = described_class.new(results_dir: directory, state_path: state, dig:, registry:)
      expect(changed.run(["demo"]).fetch(:observed).size).to eq(1)
      expect(JSON.parse(File.read(state)).dig("gems", "demo").size).to eq(2)
      expect(dig).to have_received(:run).twice
    end
  end

  it "does not checkpoint incomplete repeated observation groups" do
    with_monitor(->(_) { [{"number" => "1"}] }) do |monitor, dig, state, _|
      allow(dig).to receive(:result_exists?).with("demo", phase: "all", version: "1").and_return(false)
      expect(monitor.run(["demo"]).fetch(:errors).size).to eq(1)
      expect(File.exist?(state)).to be(false)
    end
  end

  it "bounds registry response size and rejects HTTP errors without advancing state" do
    response = Net::HTTPOK.new("1.1", "200", "OK")
    allow(response).to receive(:read_body).and_yield("x" * (described_class::RESPONSE_LIMIT + 1))
    client = double
    allow(client).to receive(:request_get).and_yield(response)
    allow(Net::HTTP).to receive(:start).and_yield(client)
    with_monitor(nil) do |monitor, dig, state, _|
      expect(monitor.run(["demo"]).fetch(:errors).first.fetch(:error)).to include("response exceeds")
      allow(client).to receive(:request_get).and_yield(Net::HTTPNotFound.new("1.1", "404", "Not found"))
      expect(monitor.run(["demo"]).fetch(:errors).first.fetch(:error)).to include("HTTP 404")
      expect(File.exist?(state)).to be(false)
      expect(dig).not_to have_received(:run)
    end
  end

  it "rejects corrupt state and unsafe gem names before executing targets" do
    with_monitor(->(_) { [{"number" => "1"}] }) do |monitor, dig, state, _|
      expect { monitor.run(["../demo"]) }.to raise_error(ArgumentError)
      File.write(state, "{")
      expect { monitor.run(["demo"]) }.to raise_error(ArgumentError, /state/)
      expect(dig).not_to have_received(:run)
      expect(File.read(state)).to eq("{")
    end
  end
end
