# frozen_string_literal: true

require "tempfile"

RSpec.describe Bonebed::Survey do
  it "extracts unique gem names from the official stats pages" do
    html = '<a href="/gems/rake">rake</a><a href="/gems/json?locale=en">json</a><a href="/gems/rake">rake</a>'

    expect(described_class.send(:names_from, html)).to eq(%w[rake json rake])
  end

  it "parses names and optional versions from a text file" do
    file = Tempfile.new
    file.write("rake 13.4.2\njson # latest\n\n")
    file.close

    expect(described_class.file(file.path)).to eq([
      {name: "rake", version: "13.4.2"},
      {name: "json", version: nil}
    ])
  ensure
    file&.unlink
  end

  it "uses Bundler's parser for lockfile versions" do
    path = File.join(__dir__, "fixtures", "Gemfile.lock")

    expect(described_class.lockfile(path)).to eq([{name: "rake", version: "13.4.2"}])
  end
end
