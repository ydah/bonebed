# frozen_string_literal: true

require "tempfile"

RSpec.describe Bonebed::Survey do
  it "continues after target errors and reports failure" do
    dig = instance_double(Bonebed::Dig, result_exists?: false, last_observer_errors: [], run: nil)
    allow(dig).to receive(:last_errors).and_return([], ["failed"])
    entries = [{name: "rake", version: nil}, {name: "json", version: nil}]

    expect(described_class.new(dig:, output: StringIO.new).run(entries, phase: "require")).to be(false)
    expect(dig).to have_received(:run).twice
  end

  it "continues after a missing gem and records its failure" do
    error = Gem::LoadError.new("missing gem")
    dig = instance_double(Bonebed::Dig, result_exists?: false, last_observer_errors: [], run: nil, last_errors: [], write_failure: nil)
    allow(dig).to receive(:run).with("missing", phase: "require", version: nil, require_path: nil).and_raise(error)
    entries = [{name: "missing", version: nil}, {name: "rake", version: nil}]

    expect(described_class.new(dig:, output: StringIO.new).run(entries, phase: "require")).to be(false)
    expect(dig).to have_received(:run).twice
    expect(dig).to have_received(:write_failure).with("missing", phase: "require", version: "unknown", error:)
  end

  it "passes an entry's require path to dig" do
    dig = instance_double(Bonebed::Dig, result_exists?: false, last_observer_errors: [], run: nil, last_errors: [])
    entry = {name: "sinatra", version: nil, require_path: "sinatra/base"}

    expect(described_class.new(dig:, output: StringIO.new).run([entry], phase: "require")).to be(true)
    expect(dig).to have_received(:run).with("sinatra", phase: "require", version: nil, require_path: "sinatra/base")
  end

  it "reclaims unreachable objects after every survey entry" do
    dig = instance_double(Bonebed::Dig, result_exists?: false, last_observer_errors: [], run: nil, last_errors: [])
    allow(GC).to receive(:start)

    described_class.new(dig:, output: StringIO.new).run([{name: "rake"}, {name: "json"}], phase: "require")

    expect(GC).to have_received(:start).twice
  end

  it "runs isolated survey entries in fresh processes" do
    file = Tempfile.new
    path = file.path
    file.close
    dig = Object.new
    dig.define_singleton_method(:result_exists?) { |*| false }
    dig.define_singleton_method(:run) do |*|
      File.open(path, "a") { |output| output.puts(Process.pid) }
      @last_errors = []
    end
    dig.define_singleton_method(:last_errors) { @last_errors }
    dig.define_singleton_method(:last_observer_errors) { ["observer warning"] }

    expect(described_class.new(dig:, output: StringIO.new, isolate: true).run([{name: "rake"}, {name: "json"}], phase: "require")).to be(true)
    expect(File.readlines(path, chomp: true).map(&:to_i)).to all(satisfy { |pid| pid != Process.pid })
  ensure
    file&.unlink
  end

  it "continues after an isolated worker is killed" do
    file = Tempfile.new
    path = file.path
    file.close
    dig = Object.new
    dig.define_singleton_method(:result_exists?) { |*| false }
    dig.define_singleton_method(:run) do |name, **|
      Process.kill("KILL", Process.pid) if name == "killed"
      File.open(path, "a") { |output| output.puts(name) }
      @last_errors = []
    end
    dig.define_singleton_method(:last_errors) { @last_errors }
    dig.define_singleton_method(:last_observer_errors) { ["observer warning"] }
    dig.define_singleton_method(:write_failure) { |*| nil }
    entries = [{name: "killed"}, {name: "continued"}]

    expect(described_class.new(dig:, output: StringIO.new, isolate: true).run(entries, phase: "require")).to be(false)
    expect(File.read(path)).to eq("continued\n")
  ensure
    file&.unlink
  end

  it "extracts unique gem names from the official stats pages" do
    html = '<a href="/gems/rake">rake</a><a href="/gems/json?locale=en">json</a><a href="/gems/rake">rake</a>'

    expect(described_class.send(:names_from, html)).to eq(%w[rake json rake])
  end

  it "parses names and optional versions from a text file" do
    file = Tempfile.new
    file.write("rake 13.4.2\njson # latest\nsinatra - sinatra/base\n\n")
    file.close

    expect(described_class.file(file.path)).to eq([
      {name: "rake", version: "13.4.2"},
      {name: "json", version: nil},
      {name: "sinatra", version: nil, require_path: "sinatra/base"}
    ])
  ensure
    file&.unlink
  end

  it "uses Bundler's parser for lockfile versions" do
    path = File.join(__dir__, "fixtures", "Gemfile.lock")

    expect(described_class.lockfile(path)).to eq([{name: "rake", version: "13.4.2"}])
  end
end
