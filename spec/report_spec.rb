# frozen_string_literal: true

RSpec.describe Bonebed::Report do
  it "summarizes network, notable files, commands, and open counts as Markdown" do
    Dir.mktmpdir do |directory|
      manifest = {
        gem: {name: "demo", version: "1.0.0"}, phase: "require", errors: [],
        files: {read: ["$HOME/.demo", "$PWD/config/demo.yml"], write: ["$PWD/log/demo.log"]}, network: [{family: "inet"}],
        exec: [{path: "/usr/bin/git", argv: ["git", "status"], count: 2},
          {path: "/usr/bin/git", argv: ["git", "log"], count: 1}], stats: {openat_after_baseline: 3}
      }
      File.write(File.join(directory, "demo.json"), JSON.generate(manifest))
      File.write(File.join(directory, "failed.json"), JSON.generate(manifest.merge(
        gem: {name: "broken", version: "2.0.0"}, errors: ["target exited with status 1"],
        network: [{family: "unix"}], stdout: "starting service", stderr: "LoadError: broken | gem"
      )))

      report = described_class.new(directory).markdown

      expect(report).to include("Require phase with IP sockets: 1", "Require phase with Unix sockets: 1", "`$HOME/.demo` | 2",
        "## Project files read", "`$PWD/config/demo.yml` | 2", "## Project files written", "`$PWD/log/demo.log` | 2",
        "`demo 1.0.0 (require)` | 3 | 1", "<summary>All command paths</summary>",
        "`demo 1.0.0 (require)` | `/usr/bin/git` | 3", "`broken 2.0.0 (require)` | `/usr/bin/git` | 3",
        "`broken 2.0.0 (require)` | target exited with status 1 | starting service | LoadError: broken \\| gem")
    end
  end

  it "does not truncate commands" do
    Dir.mktmpdir do |directory|
      manifest = {
        gem: {name: "demo", version: "1.0.0"}, phase: "install", errors: [], files: {read: [], write: []}, network: [],
        exec: 21.times.map { |index| {path: "/usr/bin/tool#{index}", count: 1} }, stats: {openat_after_baseline: 0}
      }
      File.write(File.join(directory, "demo.json"), JSON.generate(manifest))

      expect(described_class.new(directory).markdown).to include("`/usr/bin/tool20`")
    end
  end

  it "keeps complete failure output outside the summary table" do
    Dir.mktmpdir do |directory|
      manifest = {
        gem: {name: "native", version: "1.0.0"}, phase: "install", errors: ["target exited with status 1"],
        files: {read: [], write: []}, network: [], exec: [], stats: {openat_after_baseline: 0},
        stdout: "Building extension\n", stderr: (["build step"] * 100 + ["compiler root cause"]).join("\n")
      }
      File.write(File.join(directory, "native.json"), JSON.generate(manifest))

      report = described_class.new(directory).markdown

      expect(report).to include("<summary>Full failure output</summary>", "compiler root cause")
    end
  end
end
