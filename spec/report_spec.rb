# frozen_string_literal: true

RSpec.describe Bonebed::Report do
  it "summarizes network, home reads, commands, and open counts as Markdown" do
    Dir.mktmpdir do |directory|
      manifest = {
        gem: {name: "demo", version: "1.0.0"}, phase: "require", errors: [],
        files: {read: ["$HOME/.demo"], write: []}, network: [{family: "inet"}],
        exec: [{path: "/usr/bin/git", argv: ["git", "status"], count: 2},
          {path: "/usr/bin/git", argv: ["git", "log"], count: 1}], stats: {openat_after_baseline: 3}
      }
      File.write(File.join(directory, "demo.json"), JSON.generate(manifest))
      File.write(File.join(directory, "failed.json"), JSON.generate(manifest.merge(
        gem: {name: "broken", version: "2.0.0"}, errors: ["target exited with status 1"], stderr: "LoadError: broken | gem"
      )))

      report = described_class.new(directory).markdown

      expect(report).to include("Require phase with network: 2", "`$HOME/.demo` | 2",
        "`demo 1.0.0 (require)` | `/usr/bin/git` | 3", "`broken 2.0.0 (require)` | `/usr/bin/git` | 3",
        "`broken 2.0.0 (require)` | target exited with status 1 | LoadError: broken \\| gem")
    end
  end
end
