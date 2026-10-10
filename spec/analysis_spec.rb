# frozen_string_literal: true

require "bonebed/capability_keys"
require "bonebed/manifest_diff"
require "bonebed/policy"
require "bonebed/sarif"
require "tmpdir"

RSpec.describe "manifest analysis" do
  let(:manifest) do
    {"schema_version" => 2, "gem" => {"name" => "demo", "version" => "1.2.3"}, "phase" => "install",
     "files" => {"read" => {"self" => [], "resolver" => [], "other" => ["$HOME/.aws/credentials"]}, "write" => ["$PWD/.git/hooks/pre-commit"]},
     "network" => [{"family" => "inet", "addr" => "127.0.0.1", "port" => 443, "count" => 2}],
     "exec" => [{"path" => "/usr/bin/make", "argv" => ["make"], "count" => 3}], "threads" => []}
  end

  it "flattens both schema versions to the same deterministic keys" do
    legacy = Marshal.load(Marshal.dump(manifest))
    legacy["schema_version"] = 1
    legacy["files"]["read"] = ["$HOME/.aws/credentials"]
    expect(Bonebed::CapabilityKeys.call(manifest)).to eq(Bonebed::CapabilityKeys.call(legacy))
    expect(Bonebed::CapabilityKeys.call(manifest)).to eq([
      "exec:/usr/bin/make", "file:read:$HOME/.aws/credentials", "file:write:$PWD/.git/hooks/pre-commit", "network:inet:127.0.0.1:443"
    ])
  end

  it "includes DNS, process creation, file changes, servers, and suspicious calls" do
    manifest.merge!("dns" => ["api.example.invalid"], "processes" => [{"syscall" => "clone", "count" => 2}],
      "listen" => [{"family" => "inet6", "addr" => "::1", "port" => 8080}], "suspicious" => [{"syscall" => "memfd_create"}])
    manifest["files"]["rename"] = [{"from" => "$PWD/a", "to" => "$PWD/b"}]
    expect(Bonebed::CapabilityKeys.call(manifest)).to include("network:dns:api.example.invalid", "process:spawn",
      "listen:inet6:[::1]:8080", "syscall:memfd_create", "file:rename:$PWD/a:$PWD/b")
  end

  it "compares sinkhole destinations and evaluates them as install network activity" do
    manifest["network_intent"] = [{"protocol" => "http", "host" => "api.example.invalid", "path" => "/collect", "method" => "POST"},
      {"protocol" => "tls", "host" => "secure.example.invalid", "count" => 2}]
    keys = Bonebed::CapabilityKeys.counts(manifest)
    expect(keys).to include("network:http:api.example.invalid" => 1, "network:tls:secure.example.invalid" => 2)
    findings = Bonebed::Policy.new.violations(manifest).select { |finding| finding["rule_id"] == "install-network" }
    expect(findings.map { |finding| finding["capability"] }).to include("network:http:api.example.invalid", "network:tls:secure.example.invalid")
    manifest["network_intent"].first["protocol"] = "unknown"
    expect { Bonebed::CapabilityKeys.call(manifest) }.to raise_error(ArgumentError, /protocol/)
  end

  it "ignores count changes unless requested and reports added and removed keys" do
    newer = Marshal.load(Marshal.dump(manifest))
    newer["network"][0]["count"] = 9
    expect(Bonebed::ManifestDiff.call(manifest, newer)).to eq("added" => [], "removed" => [])
    expect(Bonebed::ManifestDiff.call(manifest, newer, counts: true)["counts"])
      .to eq("network:inet:127.0.0.1:443" => {"before" => 2, "after" => 9})
    newer["exec"] = [{"path" => "/usr/bin/curl"}]
    expect(Bonebed::ManifestDiff.call(manifest, newer)).to eq("added" => ["exec:/usr/bin/curl"], "removed" => ["exec:/usr/bin/make"])
  end

  it "includes socket types and flags raw or packet socket creation" do
    manifest["sockets"] = [{"family" => "inet", "type" => 3, "protocol" => 1, "count" => 2},
      {"family" => "packet", "type" => 2, "protocol" => 0}]
    expect(Bonebed::CapabilityKeys.counts(manifest)).to include("socket:inet:3:1" => 2, "socket:packet:2:0" => 1)
    expect(Bonebed::Policy.new.findings(manifest).count { |entry| entry["rule_id"] == "raw-socket" }).to eq(2)
    manifest["sockets"][0]["type"] = "3"
    expect { Bonebed::CapabilityKeys.call(manifest) }.to raise_error(ArgumentError)
  end

  it "normalizes package versions and hashes only for diffing while retaining real new file access" do
    before = Marshal.load(Marshal.dump(manifest))
    after = Marshal.load(Marshal.dump(manifest))
    [before, after].zip(%w[1.2.3 2.0.0], %w[a b]).each do |data, version, digest|
      data["gem"]["version"] = version
      data["files"]["read"]["self"] = ["$GEM_HOME/gems/demo-#{version}/lib/demo.rb"]
      data["files"]["read"]["other"] += ["$GEM_HOME/specifications/demo-#{version}.gemspec", "$TMPDIR/<random>/#{digest * 64}.gem"]
      data["files"]["write"] += ["$GEM_HOME/cache/demo-#{version}.gem", "$GEM_HOME/extensions/x86_64-linux/4.0.0/demo-#{version}/gem.build_complete"]
    end
    expect(Bonebed::ManifestDiff.call(before, after)).to eq("added" => [], "removed" => [])
    expect(Bonebed::CapabilityKeys.call(after)).to include("file:read:$GEM_HOME/gems/demo-2.0.0/lib/demo.rb")
    after["files"]["read"]["self"] << "$GEM_HOME/gems/demo-2.0.0/lib/extra.rb"
    after["files"]["read"]["other"] << "/etc/shadow"
    expect(Bonebed::ManifestDiff.call(before, after)["added"]).to contain_exactly("file:read:$GEM_HOME/gems/demo-<version>/lib/extra.rb", "file:read:/etc/shadow")
  end

  it "rejects malformed manifests instead of silently skipping capabilities" do
    [{"schema_version" => 8}, manifest.merge("network" => "invalid"), manifest.merge("files" => {"read" => 1})].each do |invalid|
      expect { Bonebed::CapabilityKeys.call(invalid) }.to raise_error(ArgumentError)
    end
  end

  it "evaluates default rules and the high severity threshold" do
    policy = Bonebed::Policy.new
    expect(policy.violations(manifest).map { |finding| finding["rule_id"] }).to contain_exactly("credential-read", "git-hook-write", "install-network")
    expect(policy.violations(manifest, fail_on: "medium").map { |finding| finding["rule_id"] }).to include("external-command")
    manifest["phase"] = "require"
    expect(policy.findings(manifest).map { |finding| finding["rule_id"] }).not_to include("install-network")
  end

  it "applies glob permissions only to matching gems and phases" do
    policy = Bonebed::Policy.new("allow" => {"dem*" => {"install" => ["file:read:$HOME/.aws/**"]}})
    finding = policy.findings(manifest).find { |entry| entry["rule_id"] == "credential-read" }
    expect(finding["allowed"]).to be(true)
    expect(policy.violations(manifest).map { |entry| entry["rule_id"] }).not_to include("credential-read")
    manifest["phase"] = "require"
    expect(policy.violations(manifest).map { |entry| entry["rule_id"] }).to include("credential-read")
  end

  it "evaluates explicit diff keys with the same phase rules and permissions" do
    policy = Bonebed::Policy.new("allow" => {"demo" => {"install" => ["exec:**"]}})
    findings = policy.findings(manifest, keys: ["exec:/usr/bin/new-tool", "network:inet:192.0.2.1:443"])
    expect(findings).to contain_exactly(include("rule_id" => "external-command", "severity" => "medium", "allowed" => true),
      include("rule_id" => "install-network", "severity" => "high", "allowed" => false))
    expect(policy.findings(manifest, keys: [])).to eq([])
  end

  it "supports disabled and overridden rules with validated defaults" do
    policy = Bonebed::Policy.new("defaults" => {"fail_on" => "critical"}, "rules" => {"extends" => "default", "disable" => ["git-hook-write"],
                                                                                      "custom" => [{"id" => "install-network", "severity" => "low", "match" => ["network:**"], "message" => "Reviewed network"}]})
    expect(policy.violations(manifest).map { |entry| entry["rule_id"] }).to eq(["credential-read"])
    expect(policy.defaults).to include("fail_on" => "critical")
  end

  it "rejects unknown fields, malformed permissions, severities, and duplicate custom IDs" do
    invalid_configs = [[], {"version" => 9}, {"allows" => {}}, {"defaults" => {"fail_on" => "hgh"}},
      {"allow" => {"demo" => {"require" => "*"}}}, {"rules" => {"extends" => "../other.yml"}},
      {"rules" => {"disable" => ["unknown-rule"]}}, {"rules" => {"custom" => [{"id" => "a", "severity" => "high", "match" => []}]}},
      {"rules" => {"custom" => Array.new(2) { {"id" => "a", "severity" => "high", "match" => ["exec:**"]} }}}]
    invalid_configs.each { |config| expect { Bonebed::Policy.new(config) }.to raise_error(ArgumentError) }
  end

  it "loads YAML safely without object deserialization or aliases" do
    Dir.mktmpdir do |root|
      path = File.join(root, ".bonebed.yml")
      File.write(path, "version: 1\ndefaults:\n  fail_on: medium\n")
      expect(Bonebed::Policy.load(path).defaults["fail_on"]).to eq("medium")
      ["--- !ruby/object:Object {}", "allow: &all {}\nrules: *all"].each do |yaml|
        File.write(path, yaml)
        expect { Bonebed::Policy.load(path) }.to raise_error(ArgumentError, /policy/)
      end
    end
  end

  it "locates SARIF findings on the exact gem version in the lockfile" do
    Dir.mktmpdir do |root|
      lockfile = File.join(root, "Gemfile.lock")
      File.write(lockfile, "GEM\n  specs:\n    demo-extra (1.2.3)\n    demo (1.2.3)\n    demo (2.0.0)\n")
      sarif = Bonebed::Sarif.call([manifest], policy: Bonebed::Policy.new, lockfile:, source_root: root)
      expect(sarif["version"]).to eq("2.1.0")
      run = sarif.fetch("runs").first
      expect(run["results"].size).to eq(4)
      expect(run["results"].map { |result| result["level"] }).to include("error", "warning")
      expect(run["results"].first.dig("locations", 0, "physicalLocation", "region", "startLine")).to eq(4)
      expect(run["results"].first.dig("locations", 0, "physicalLocation", "artifactLocation", "uri")).to eq("Gemfile.lock")
      expect { JSON.generate(sarif) }.not_to raise_error
    end
  end

  it "omits allowed SARIF findings and supports manifests without a lockfile" do
    policy = Bonebed::Policy.new("allow" => {"*" => {"*" => ["**"]}})
    expect(Bonebed::Sarif.call([manifest], policy:).dig("runs", 0, "results")).to be_empty
    expect(Bonebed::Sarif.call([manifest]).dig("runs", 0, "results").first).not_to have_key("locations")
  end

  it "rejects malformed saved findings and unsafe reference URLs" do
    [nil, [false], [{"rule_id" => "test", "severity" => "urgent", "message" => "test", "capability" => "exec:test"}],
      [{"rule_id" => "test", "severity" => "high", "message" => "test", "capability" => "exec:test", "references" => ["javascript:alert(1)"]}]].each do |findings|
      expect { Bonebed::Sarif.call([manifest.merge("findings" => findings)]) }.to raise_error(ArgumentError)
    end
    expect { Bonebed::Sarif.artifact_uri("../Gemfile.lock", Dir.pwd) }.to raise_error(ArgumentError)
  end
end
