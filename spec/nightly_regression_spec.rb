# frozen_string_literal: true

require "bonebed/nightly_regression"

RSpec.describe "Nightly regression reports" do
  def manifest(version: "1.0.0", phase: "require", **changes)
    {"schema_version" => 2, "gem" => {"name" => "example", "version" => version, "platform" => "ruby", "require_path" => "example"},
     "tool" => {"name" => "bonebed", "version" => "0.2.0", "seccomp_notify" => "0.3.0"},
     "phase" => phase, "environment" => {"ruby" => "4.0.6", "arch" => "aarch64", "kernel" => "6.12"},
     "run" => {"mode" => {"offline" => true, "sinkhole" => false, "honeypot" => true, "env_profile" => "dev", "writes_only" => false,
                          "real_home" => false, "cwd" => nil, "enforce" => nil, "deny" => nil, "isolation" => "network_namespace"}},
     "files" => {"read" => {"self" => ["$GEM_HOME/gems/example-#{version}/lib/example.rb"], "resolver" => [], "other" => []}, "write" => []},
     "network" => [], "exec" => [], "threads" => [], "errors" => [], "observer_errors" => [],
     "target" => {"exit_status" => 0, "signal" => nil, "timed_out" => false}}.merge(changes.transform_keys(&:to_s))
  end

  it "separates version changes from new capabilities and attaches default-policy severity" do
    before = manifest
    after = manifest(version: "2.0.0")
    after["files"]["read"]["other"] = ["$HOME/.aws/credentials"]
    report = Bonebed::NightlyRegression.compare(current: [after], previous: [before])
    row = report.fetch("observations").fetch(0)
    expect(row).to include("status" => "compared", "version_changed" => true, "before_version" => "1.0.0", "after_version" => "2.0.0")
    expect(row["added"]).to eq(["file:read:$HOME/.aws/credentials"])
    expect(row["removed"]).to be_empty
    expect(row["findings"]).to include(include("severity" => "critical", "rule_id" => "credential-read"))
    expect(report).not_to have_key("safe")
  end

  it "reports first runs, missing targets, failures and incompatible observation contexts" do
    expect(Bonebed::NightlyRegression.compare(current: [manifest], previous: nil)["observations"].first)
      .to include("status" => "not_compared", "reason" => "no_previous_observations")
    expect(Bonebed::NightlyRegression.compare(current: [], previous: [manifest])["observations"].first)
      .to include("status" => "missing_current")
    [
      [manifest(target: {}), "current_failed"],
      [manifest(tool: {}), "unknown_runtime"],
      [manifest(phase: "bundler_plugin"), "new_target"],
      [manifest(errors: ["target failed"]), "current_failed"],
      [manifest(observer_errors: ["decoder failed"]), "current_failed"],
      [manifest(environment: {"ruby" => "3.4.0", "arch" => "aarch64", "kernel" => "6.12"}), "runtime_changed"],
      [manifest(run: {"mode" => manifest.dig("run", "mode").merge("offline" => false)}), "mode_changed"],
      [manifest(environment: {}), "unknown_runtime"],
      [manifest(run: {"mode" => {}}), "unknown_mode"]
    ].each do |current, reason|
      expect(Bonebed::NightlyRegression.compare(current: [current], previous: [manifest])["observations"].first)
        .to include("reason" => reason)
    end
    expect(Bonebed::NightlyRegression.compare(current: [manifest, manifest(version: "2")], previous: [manifest])["observations"].first)
      .to include("reason" => "ambiguous_observations")
  end

  it "reports malformed saved data without silently treating it as an empty successful run" do
    Dir.mktmpdir do |directory|
      File.write(File.join(directory, "broken.json"), "{invalid")
      result = Bonebed::NightlyRegression.read(directory)
      expect(result.fetch("manifests")).to be_empty
      expect(result.fetch("errors")).to include(include("path" => "broken.json"))
    end
  end

  it "requires the observer and Bundler versions to match before comparing plugin observations" do
    before = manifest(phase: "bundler_plugin")
    after = Marshal.load(Marshal.dump(before))
    expect(Bonebed::NightlyRegression.incompatible(before, after)).to eq("unknown_runtime")
    [before, after].each { |entry| entry["environment"]["bundler"] = "2.5.22" }
    expect(Bonebed::NightlyRegression.incompatible(before, after)).to be_nil
    after["environment"]["bundler"] = "2.6.0"
    expect(Bonebed::NightlyRegression.incompatible(before, after)).to eq("runtime_changed")
    after["environment"]["bundler"] = "2.5.22"
    %w[name version seccomp_notify].each do |key|
      changed = after.merge("tool" => after.fetch("tool").merge(key => "different"))
      expect(Bonebed::NightlyRegression.incompatible(before, changed)).to eq("runtime_changed")
    end
  end

  it "compares benchmark summaries only for matching complete environment metadata" do
    environment = {"ruby" => "4.0.6", "arch" => "aarch64", "kernel" => "6.12", "cpu" => "fixture", "cpus" => 2,
                   "tool" => "bonebed", "tool_version" => "0.2.0", "workload" => "read-hostname-1000-v1", "writes_only" => false, "seccomp_notify" => "0.1.0"}
    before = {"environment" => environment, "samples" => [{"plain_ms" => 10, "observed_ms" => 100, "ratio" => 10, "notifications" => 1000}]}
    after = before.merge("samples" => [{"plain_ms" => 20, "observed_ms" => 120, "ratio" => 6, "notifications" => 1000}])
    report = Bonebed::NightlyRegression.benchmark(after, before)
    expect(report).to include("status" => "compared")
    expect(report.dig("changes", "observed_ms")).to include("before" => 100, "after" => 120, "delta" => 20)
    expect(Bonebed::NightlyRegression.benchmark(after.merge("environment" => environment.merge("cpu" => "other")), before))
      .to include("reason" => "environment_changed")
    expect(Bonebed::NightlyRegression.benchmark(after.except("environment"), before)).to include("reason" => "unknown_environment")
    expect(Bonebed::NightlyRegression.benchmark(after, nil)).to include("reason" => "no_previous_benchmark")
  end
end
