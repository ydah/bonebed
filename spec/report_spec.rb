# frozen_string_literal: true

RSpec.describe Bonebed::Report do
  it "summarizes network, home reads, commands, and open counts as Markdown" do
    Dir.mktmpdir do |directory|
      manifest = {
        gem: {name: "demo", version: "1.0.0"}, phase: "require", errors: [],
        files: {read: ["$HOME/.demo"], write: []}, network: [{family: "inet"}],
        exec: [{path: "/usr/bin/git", count: 2}], stats: {openat_after_baseline: 3}
      }
      File.write(File.join(directory, "demo.json"), JSON.generate(manifest))

      report = described_class.new(directory).markdown

      expect(report).to include("Require phase with network: 1", "`$HOME/.demo` | 1", "`/usr/bin/git` | 2", "demo 1.0.0 (require)")
    end
  end
end
