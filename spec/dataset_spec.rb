# frozen_string_literal: true

require "bonebed/dataset"

RSpec.describe Bonebed::Dataset do
  def observation(version, **overrides)
    {"schema_version" => 1, "gem" => {"name" => "demo", "version" => version, "platform" => "ruby"}, "phase" => "require",
     "files" => {"read" => [], "write" => []}, "network" => [], "exec" => [], "threads" => [], "stats" => {}, "errors" => [],
     "tool" => {"name" => "bonebed", "version" => "test"}, "environment" => {"kernel" => "test-kernel"}}.merge(overrides.transform_keys(&:to_s))
  end

  def with_dataset(manifests)
    Dir.mktmpdir do |root|
      results = File.join(root, "results")
      Dir.mkdir(results)
      manifests.each_with_index { |manifest, index| File.write(File.join(results, "#{index}.json"), JSON.generate(manifest)) }
      yield described_class.new(results), File.join(root, "site")
    end
  end

  it "exports a searchable site, reproducible observations, version changes, and factual badges" do
    network = [{"family" => "inet", "addr" => "127.0.0.1", "port" => 443}]
    with_dataset([observation("1.9"), observation("1.10", network:)]) do |dataset, output|
      expect(dataset.write(output)).to eq(output)
      index = File.read(File.join(output, "index.html"))
      expect(index).to include('type="search"', "demo", "observation", 'href="gems/demo.html"')
      gem = File.read(File.join(output, "gems", "demo.html"))
      expect(gem).to include("1.9", "1.10", "test-kernel", "correction")
      changes = JSON.parse(File.read(File.join(output, "changes.json")))
      expect(changes.fetch(0)).to include("from" => "1.9", "to" => "1.10", "added" => ["network:inet:127.0.0.1:443"], "removed" => [])
      expect(File.read(File.join(output, "changes.rss"))).to include("<rss version=\"2.0\">", "demo 1.9 → 1.10")
      expect(JSON.parse(File.read(File.join(output, "badges", "demo.json")))).to include("schemaVersion" => 1, "message" => "observed", "label" => "network activity")
      exported = JSON.parse(File.read(File.join(output, "manifests.json")))
      expect(exported.first.fetch("environment")).to eq("kernel" => "test-kernel")
      expect(JSON.parse(File.read(File.join(output, "search-index.json")))).to include(hash_including("name" => "demo"))
    end
  end

  it "escapes HTML and XML rather than executing capability or metadata text" do
    path = '/tmp/<script>alert("x")</script>&'
    with_dataset([observation("1"), observation("2", exec: [{"path" => path}])]) do |dataset, output|
      dataset.write(output)
      page = File.read(File.join(output, "gems", "demo.html"))
      feed = File.read(File.join(output, "changes.rss"))
      expect(page).not_to include(path)
      expect(page).to include("&lt;script&gt;")
      expect(feed).to include("&lt;script&gt;", "&amp;")
      expect(feed).not_to include("<script>")
    end
  end

  it "does not compare different phases or platforms as if they were version changes" do
    alternate = observation("2", phase: "install", network: [{"family" => "netlink"}])
    with_dataset([observation("1"), alternate]) do |dataset, output|
      dataset.write(output)
      expect(JSON.parse(File.read(File.join(output, "changes.json")))).to be_empty
    end
  end

  it "marks network absence as unknown when the latest observation failed" do
    with_dataset([observation("1"), observation("2", target: {"exit_status" => 1})]) do |dataset, output|
      dataset.write(output)
      expect(JSON.parse(File.read(File.join(output, "badges", "demo.json"))).fetch("message")).to eq("unknown")
    end
  end

  it "does not describe a change of observation mode as a release change" do
    with_dataset([observation("1", run: {"mode" => {"offline" => true}}),
      observation("2", run: {"mode" => {"offline" => false}}, network: [{"family" => "netlink"}])]) do |dataset, output|
      dataset.write(output)
      expect(JSON.parse(File.read(File.join(output, "changes.json")))).to be_empty
    end
  end

  it "compares the union of repeat samples across distinct versions" do
    manifests = %w[1 2].flat_map do |version|
      [observation(version, run: {"mode" => {"repeat" => 2}, "repeat" => {"group" => version, "index" => 1, "count" => 2}}),
        observation(version, run: {"mode" => {"repeat" => 2}, "repeat" => {"group" => version, "index" => 2, "count" => 2}},
          exec: [{"path" => "/usr/bin/helper#{version}"}])]
    end
    with_dataset(manifests) do |dataset, output|
      dataset.write(output)
      changes = JSON.parse(File.read(File.join(output, "changes.json")))
      expect(changes.size).to eq(1)
      expect(changes.first).to include("from" => "1", "to" => "2", "added" => ["exec:/usr/bin/helper2"], "removed" => ["exec:/usr/bin/helper1"])
    end
  end

  it "keeps distinct executable invocations out of release comparisons" do
    with_dataset([observation("1", phase: "exec", run: {"executable" => "demo", "arguments" => ["--help"]}),
      observation("2", phase: "exec", run: {"executable" => "demo", "arguments" => ["upload"]}, network: [{"family" => "netlink"}])]) do |dataset, output|
      dataset.write(output)
      expect(JSON.parse(File.read(File.join(output, "changes.json")))).to be_empty
    end
  end

  it "augments matching CycloneDX gems without changing the input or non-gem components" do
    with_dataset([observation("1", exec: [{"path" => "/usr/bin/make"}])]) do |dataset, _|
      sbom = {"bomFormat" => "CycloneDX", "specVersion" => "1.6", "components" => [
        {"name" => "demo", "version" => "1", "purl" => "pkg:gem/demo@1", "properties" => [{"name" => "existing", "value" => "yes"}]},
        {"name" => "demo", "version" => "1", "purl" => "pkg:npm/demo@1"}, {"name" => "other", "version" => "1"}
      ]}
      augmented = dataset.augment_sbom(sbom)
      expect(augmented["components"][0]["properties"]).to include("name" => "existing", "value" => "yes")
      property = augmented["components"][0]["properties"].find { |entry| entry["name"] == "bonebed:capabilities" }
      expect(JSON.parse(property.fetch("value"))).to eq(["exec:/usr/bin/make"])
      expect(augmented["components"][1..]).to eq(sbom["components"][1..])
      expect(sbom["components"][0]["properties"].size).to eq(1)
      expect(dataset.augment_sbom(augmented)).to eq(augmented)
      expect { dataset.augment_sbom({}) }.to raise_error(ArgumentError)
      expect { dataset.augment_sbom("bomFormat" => "CycloneDX", "components" => [{"purl" => 7}]) }.to raise_error(ArgumentError)
    end
  end

  it "refuses symlink destinations instead of writing outside the selected output directory" do
    with_dataset([observation("1")]) do |dataset, output|
      Dir.mkdir(output)
      victim = File.join(File.dirname(output), "victim")
      File.write(victim, "keep")
      File.symlink(victim, File.join(output, "index.html"))
      expect { dataset.write(output) }.to raise_error(ArgumentError, /symlink/)
      expect(File.read(victim)).to eq("keep")
    end
  end
end
