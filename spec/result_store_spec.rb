# frozen_string_literal: true

require "bonebed/result_store"
require "bonebed/manifest_builder"
require "json_schemer"

RSpec.describe Bonebed::ResultStore do
  let(:schema) { JSONSchemer.schema(JSON.parse(File.read(File.expand_path("../schema/manifest-v2.json", __dir__)))) }
  def legacy_manifest
    {"schema_version" => 1, "gem" => {"name" => "rack", "version" => "3.0.0", "require_path" => "rack"},
     "phase" => "require", "files" => {"read" => ["$HOME/.demo"], "write" => [], "notable" => ["$HOME/.demo"]},
     "network" => [], "exec" => [], "threads" => [], "stats" => {"openat_total" => 4, "openat_after_baseline" => 1},
     "errors" => [], "stdout" => "", "stderr" => ""}
  end

  it "migrates without deleting originals, preserving observations and marking missing metadata unknown" do
    Dir.mktmpdir do |directory|
      original = File.join(directory, "rack-3.0.0-require.json")
      File.write(original, JSON.generate(legacy_manifest))
      store = described_class.new(directory)
      paths = store.migrate
      migrated = JSON.parse(File.read(paths.fetch(0)))

      expect(File.exist?(original)).to be(true)
      expect(migrated.fetch("schema_version")).to eq(2)
      expect(migrated.dig("files", "read", "other")).to eq(["$HOME/.demo"])
      expect(migrated.dig("stats", "open_total")).to eq(4)
      expect(migrated.dig("stats", "open_after_baseline")).to eq(1)
      expect(migrated.dig("target", "exit_status")).to be_nil
      expect(migrated.dig("gem", "sha256")).to be_nil
      expect(migrated.dig("run", "started_at")).to be_nil
      expect(migrated.dig("capabilities", "home_read")).to be(true)
      expect(schema.validate(migrated).to_a).to be_empty
      expect(described_class.read(directory).size).to eq(1)
      expect(store.migrate).to eq(paths)
      migrated["stdout"] = "newer result"
      store.write(migrated)
      store.migrate
      expect(JSON.parse(File.read(paths.first)).fetch("stdout")).to eq("newer result")
    end
  end

  it "validates schema v2 manifests built from every golden syscall profile" do
    Dir[File.join(__dir__, "fixtures", "golden", "*.json")].each do |path|
      golden = JSON.parse(File.read(path), symbolize_names: true)
      observation = {files: golden.fetch(:files).slice(:read, :write).transform_values { |paths| paths.to_h { |item| [item, 1] } },
                     network: golden.fetch(:network).to_h { |entry| [entry, 1] }, exec: golden.fetch(:exec).to_h { |entry| [entry, 1] },
                     threads: {}, errors: [], stats: {openat_total: 0, wall_ms: 0, notify_roundtrips: 0}}
      baseline = Bonebed::Baseline::Result.new(id: "test", observation: {files: {}, network: {}, exec: {}})
      manifest = Bonebed::ManifestBuilder.call("fixture", "1.0", "require", observation, baseline)
      expect(schema.validate(manifest).to_a).to be_empty, "#{path} did not match schema v2"
    end
  end

  it "keeps platforms and require paths separate and writes atomically" do
    Dir.mktmpdir do |directory|
      File.write(File.join(directory, "legacy.json"), JSON.generate(legacy_manifest))
      store = described_class.new(directory)
      manifest = JSON.parse(File.read(store.migrate.first))
      paths = [["ruby", "rack"], ["ruby", "rack/test"], ["aarch64-linux", "rack"]].map do |platform, require_path|
        store.write(manifest.merge("gem" => manifest.fetch("gem").merge("platform" => platform, "require_path" => require_path)))
      end
      expect(paths.uniq.size).to eq(3)
      expect(paths).to all(start_with(File.join(directory, "require", "rack")))
      expect(Dir[File.join(directory, "**", "*.tmp")]).to be_empty
      expect(store.exists?("rack", phase: "require", version: "3.0.0", require_path: "rack/test", platform: "ruby")).to be(true)
      expect(store.exists?("rack", phase: "require", require_path: "rack/missing")).to be(false)
    end
  end

  it "does not skip incomplete, target-failed, or prefix-colliding observations" do
    Dir.mktmpdir do |directory|
      store = described_class.new(directory)
      File.write(File.join(directory, "rack-test.json"), JSON.generate(legacy_manifest.merge("gem" => {"name" => "rack-test", "version" => "3.0.0"})))
      File.write(File.join(directory, "broken.json"), "{")
      expect(store.exists?("rack", phase: "require")).to be(false)
      [legacy_manifest.merge("errors" => ["failed"]),
        legacy_manifest.except("errors"), legacy_manifest.merge("network" => [{"family" => "inet"}])].each do |manifest|
        File.write(File.join(directory, "rack.json"), JSON.generate(manifest))
        expect(store.exists?("rack", phase: "require")).to be(false)
      end
      File.write(File.join(directory, "rack.json"), JSON.generate(legacy_manifest.merge("observer_errors" => ["lost event"])))
      expect(store.exists?("rack", phase: "require")).to be(true)
    end
  end

  it "rejects unsafe identities and malformed shapes before writing" do
    Dir.mktmpdir do |directory|
      store = described_class.new(directory)
      expect { store.write(legacy_manifest.merge("schema_version" => 2, "gem" => {"name" => "../escape", "version" => "1"})) }.to raise_error(ArgumentError)
      expect { store.write(legacy_manifest.merge("schema_version" => 2, "files" => [])) }.to raise_error(ArgumentError)
      expect(Dir.children(directory)).to be_empty
    end
  end

  it "keeps requested observation modes separate while ignoring runtime isolation details" do
    Dir.mktmpdir do |directory|
      store = described_class.new(directory)
      manifest = described_class.upgrade(legacy_manifest)
      mode = {"offline" => false, "honeypot" => true, "env_profile" => "dev", "writes_only" => false}
      modes = [mode, mode.merge("offline" => true), mode.merge("sinkhole" => true), mode.merge("env_profile" => "ci"),
        mode.merge("writes_only" => true), mode.merge("honeypot" => false), mode.merge("enforce" => "policy-a"), mode.merge("deny" => "policy-a")]
      paths = modes.map { |entry| store.write(manifest.merge("run" => {"mode" => entry})) }
      expect(paths.uniq.size).to eq(modes.size)
      expect(described_class.read(directory).size).to eq(modes.size)
      expect(store.exists?("rack", phase: "require", mode: mode.merge("enforce" => "policy-b"))).to be(false)
      expect(store.exists?("rack", phase: "require", mode: mode)).to be(true)
      expect(store.write(manifest.merge("run" => {"mode" => mode.merge("isolation" => "namespace")}))).to eq(paths.first)
      expect(store.write(manifest.merge("run" => {"mode" => mode.merge("sinkhole" => false)}))).to eq(paths.first)
    end
  end

  it "rejects malformed sinkhole intent and mode metadata" do
    manifest = described_class.upgrade(legacy_manifest)
    valid = {"protocol" => "http", "host" => "example.test", "path" => "/", "method" => "GET", "count" => 1}
    expect(described_class.valid?(manifest.merge("network_intent" => [valid]))).to be(true)
    expect(described_class.valid?(manifest.merge("network_intent" => [valid.except("count")]))).to be(true)
    expect(described_class.capabilities(manifest.merge("network_intent" => [valid]))).to include("network" => true)
    [nil, {}, [nil], [valid.merge("protocol" => "ftp")], [valid.merge("host" => "")],
      [valid.merge("count" => 0)], [valid.merge("path" => [])], [valid.merge("sample" => {})]].each do |intent|
      expect(described_class.valid?(manifest.merge("network_intent" => intent))).to be(false)
    end
    expect(described_class.valid?(manifest.merge("run" => {"mode" => {"sinkhole" => "true"}}))).to be(false)
  end

  it "validates explicit denial evidence and policy mode metadata" do
    manifest = described_class.upgrade(legacy_manifest)
    event = {"syscall" => "openat", "capability" => "file:read:$HOME/.aws/credentials", "rule_id" => "credential-read", "severity" => "critical", "count" => 1}
    expect(described_class.valid?(manifest.merge("denied" => [event]))).to be(true)
    expect(schema.validate(manifest.merge("denied" => [event])).to_a).to be_empty
    [{"count" => 0}, {"severity" => "unknown"}, {"capability" => ""}].each do |invalid|
      expect(described_class.valid?(manifest.merge("denied" => [event.merge(invalid)]))).to be(false)
    end
    expect(described_class.valid?(manifest.merge("denied" => [event.except("count")]))).to be(false)
    expect(described_class.valid?(manifest.merge("run" => {"mode" => {"deny" => true}}))).to be(false)
  end

  it "keeps distinct command argument lists separate" do
    Dir.mktmpdir do |directory|
      store = described_class.new(directory)
      manifest = described_class.upgrade(legacy_manifest).merge("phase" => "exec")
      first = store.write(manifest.merge("command" => ["ruby", "first.rb"]))
      second = store.write(manifest.merge("command" => ["ruby", "second.rb"]))
      expect(first).not_to eq(second)
      expect(described_class.read(directory).size).to eq(2)
    end
  end

  it "preserves observations from different Ruby runtimes and architectures" do
    Dir.mktmpdir do |directory|
      store = described_class.new(directory)
      manifest = described_class.upgrade(legacy_manifest)
      environments = [{"ruby" => "3.3.9", "arch" => "x86_64"}, {"ruby" => "4.0.6", "arch" => "x86_64"},
        {"ruby" => "4.0.6", "arch" => "aarch64"}]
      paths = environments.map { |environment| store.write(manifest.merge("environment" => environment)) }
      expect(paths.uniq.size).to eq(3)
      expect(described_class.read(directory).map { |item| item.fetch("environment") }).to match_array(environments)
      expect(store.matching("rack", phase: "require").all? { |item| item.dig("environment", "ruby") == RUBY_VERSION && item.dig("environment", "arch") == RbConfig::CONFIG.fetch("host_cpu") }).to be(true)
      stale = manifest.merge("environment" => {"ruby" => "0.0.0", "arch" => RbConfig::CONFIG.fetch("host_cpu")}, "gem" => manifest.fetch("gem").merge("name" => "stale"))
      store.write(stale)
      expect(store.exists?("stale", phase: "require")).to be(false)
      expect(described_class.valid?(manifest.merge("environment" => []))).to be(false)
    end
  end

  it "rejects malformed mode and command metadata without hiding valid legacy results" do
    Dir.mktmpdir do |directory|
      manifest = legacy_manifest
      [{"run" => []}, {"run" => {"mode" => []}}, {"run" => {"mode" => {"offline" => "false"}}},
        {"run" => {"repeat" => false}}, {"run" => {"arguments" => "not argv"}},
        {"gem" => manifest.fetch("gem").merge("platform" => false)}, {"command" => "ruby"}].each do |extra|
        expect(described_class.valid?(manifest.merge(extra))).to be(false)
      end
      File.write(File.join(directory, "legacy.json"), JSON.generate(manifest))
      store = described_class.new(directory)
      expect(store.exists?("rack", phase: "require")).to be(true)
      expect(store.exists?("rack", phase: "require", mode: {"offline" => false})).to be(false)
    end
  end

  it "prefers a freshly written result over an older v2 filename with the same identity" do
    Dir.mktmpdir do |directory|
      store = described_class.new(directory)
      manifest = described_class.upgrade(legacy_manifest)
      old = File.join(directory, "old-layout.json")
      File.write(old, JSON.generate(manifest.merge("stdout" => "old")))
      File.utime(Time.at(0), Time.at(0), old)
      store.write(manifest.merge("stdout" => "new"))
      expect(described_class.read(directory).map { |result| result.fetch("stdout") }).to eq(["new"])
    end
  end

  it "streams the preferred identity without retaining manifest bodies in the index" do
    Dir.mktmpdir do |directory|
      legacy = legacy_manifest
      File.write(File.join(directory, "legacy.json"), JSON.generate(legacy))
      store = described_class.new(directory)
      store.migrate
      other = described_class.upgrade(legacy).merge("gem" => legacy.fetch("gem").merge("name" => "rack-test"))
      store.write(other)
      File.write(File.join(directory, "invalid.json"), "{")
      stream = described_class.each(directory)
      expect(stream).to be_a(Enumerator)
      expect(stream.map { |manifest| [manifest.dig("gem", "name"), manifest["schema_version"]] }.sort).to eq([["rack", 2], ["rack-test", 2]])
      expect(stream.to_a).to eq(described_class.read(directory))
    end
  end
end
