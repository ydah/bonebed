# frozen_string_literal: true

require "json_schemer"

RSpec.describe "build directory attribution" do
  def specification(name)
    Gem::Specification.new do |spec|
      spec.name = name
      spec.version = "1.0"
    end
  end

  it "retains working-directory transitions and attributes only exact package directories" do
    skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux")
    Bonebed::GemEnvironment.open do |environment|
      roots = %w[one two one-extra].map { |name| File.join(environment.gem_home, "gems", "#{name}-1.0", "ext") }
      roots.each { |path| FileUtils.mkdir_p(path) }
      code = 'ARGV.each { |path| Dir.chdir(path) { File.write("build-marker", "x") } }'
      observed = Bonebed::Session.new([RbConfig.ruby, "-rrbconfig", "-e", code, *roots], env: environment.env,
        cwd: environment.project, unsetenv_others: true, quiet_target: true).run.snapshot(environment.normalizer)
      expect(observed.fetch(:errors)).to be_empty
      baseline = Bonebed::Baseline::Result.new(id: "fixture", observation: Bonebed::Collector.new.snapshot(environment.normalizer))
      manifest = Bonebed::ManifestBuilder.call("bundle", "0", "install", observed, baseline,
        specifications: [specification("one"), specification("two")])
      events = manifest.fetch("process_tree")
      attributed = events.filter_map { |event| event["attribution"] }
      expect(attributed).to include({"gem" => "one", "version" => "1.0", "source" => "cwd"},
        {"gem" => "two", "version" => "1.0", "source" => "cwd"})
      expect(events.select { |event| event["cwd"].to_s.include?("one-extra") }).not_to be_empty
      expect(events.select { |event| event["cwd"].to_s.include?("one-extra") }).to all(satisfy { |event| !event.key?("attribution") })
      schema = JSONSchemer.schema(JSON.parse(File.read(File.join(__dir__, "../schema/manifest-v2.json"))))
      expect(schema.validate(manifest).to_a).to be_empty
    end
  end

  it "classifies own writes without hiding them from policy capabilities" do
    collector = Bonebed::Collector.new
    collector.record_open(mode: :write, path: "/fixture/gems/gems/demo-1.0/cache")
    collector.record_open(mode: :write, path: "/fixture/gems/gems/demo-1.0-other/cache")
    normalizer = Bonebed::PathNormalizer.new(gem_paths: ["/fixture/gems"])
    baseline = Bonebed::Baseline::Result.new(id: "fixture", observation: Bonebed::Collector.new.snapshot(normalizer))
    manifest = Bonebed::ManifestBuilder.call("demo", "1.0", "require", collector.snapshot(normalizer), baseline,
      specifications: [specification("demo")])
    expect(manifest.dig("files", "self_write")).to eq(["$GEM_HOME/gems/demo-1.0/cache"])
    expect(Bonebed::CapabilityKeys.call(manifest)).to include("file:write:$GEM_HOME/gems/demo-1.0/cache")
    expect(Bonebed::CapabilityKeys.call(manifest).grep(/file:self_write:/)).to be_empty
  end
end
