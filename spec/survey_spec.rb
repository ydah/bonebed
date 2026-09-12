# frozen_string_literal: true

require "tempfile"

RSpec.describe Bonebed::Survey do
  it "continues after target errors and reports failure" do
    dig = instance_double(Bonebed::Dig, result_exists?: false, run: nil)
    allow(dig).to receive(:last_errors).and_return([], ["failed"])
    entries = [{name: "rake", version: nil}, {name: "json", version: nil}]

    expect(described_class.new(dig:, output: StringIO.new).run(entries, phase: "require")).to be(false)
    expect(dig).to have_received(:run).twice
  end

  it "passes an entry's require path to dig" do
    dig = instance_double(Bonebed::Dig, result_exists?: false, run: nil, last_errors: [])
    entry = {name: "sinatra", version: nil, require_path: "sinatra/base"}

    expect(described_class.new(dig:, output: StringIO.new).run([entry], phase: "require")).to be(true)
    expect(dig).to have_received(:run).with("sinatra", phase: "require", version: nil, require_path: "sinatra/base")
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
