# frozen_string_literal: true

require "bonebed/cli"

RSpec.describe "report formatters" do
  def manifest(name, writes: [], commands: [])
    {"gem" => {"name" => name, "version" => "1.0"}, "phase" => "require", "errors" => [],
     "files" => {"read" => [], "write" => writes}, "exec" => commands.map { |path| {"path" => path} },
     "network" => [], "stats" => {}}
  end

  it "gives survey Markdown a working contents list, severity order, and escaped target details" do
    Dir.mktmpdir do |directory|
      inputs = [manifest("alpha", commands: ["/usr/bin/tool"]),
        manifest("zeta", writes: ["$PWD/.git/hooks/pre-commit"]),
        manifest("quiet", writes: ["$PWD/unclassified"])]
      inputs.last["findings"] = [{"severity" => "critical", "capability" => "forged", "rule_id" => "forged"}]
      inputs.each_with_index { |input, index| File.write(File.join(directory, "#{index}.json"), JSON.generate(input)) }
      output = Bonebed::Report.new(directory).markdown
      expect(output).to include("## Contents", "[Findings](#findings)", "[Target details](#target-details)",
        "## Findings", "## Target details", "<summary>zeta 1.0 (require)</summary>")
      expect(output.index("## Contents")).to be < output.index("## Findings")
      expect(output).not_to include('</details>\\n')
      findings = output.split("## Findings", 2).last.split("## Target details", 2).first
      expect(findings.index("critical")).to be < findings.index("medium")
      expect(findings).not_to include("forged", "unclassified")
      headings = output.scan(/^## (.+)$/).flatten.map { |heading| heading.downcase.tr(" ", "-") }
      expect(output.scan(/\]\(#([a-z-]+)\)/).flatten - headings).to be_empty
    end
  end

  it "preserves explicitly evaluated policy findings for check output and sorts them by severity" do
    input = manifest("demo")
    input["findings"] = [
      {"severity" => "low", "capability" => "low capability", "rule_id" => "custom-low", "allowed" => true},
      {"severity" => "high", "capability" => "high capability", "rule_id" => "custom-high", "allowed" => false}
    ]
    output = Bonebed::CLI.format_report([input], "md")
    expect(output).to include("## Contents", "custom-low", "custom-high", "true")
    expect(output.index("high capability")).to be < output.index("low capability")
    expect(Bonebed::CLI.format_report([input], "md", policy: Bonebed::Policy.new)).not_to include("custom-high")
  end

  it "keeps HTML, Markdown, and spreadsheet escaping across formatter entrypoints" do
    input = manifest("=demo<script>![x](https://example.invalid)`|\nnext", commands: ["/bin/<img>"])
    expect(Bonebed::CLI.format_report([input], "html")).not_to include("<script>", "<img>")
    expect(Bonebed::CLI.format_report([input], "csv")).to include("\"'=demo<script>")
    markdown = Bonebed::CLI.format_report([input], "md")
    expect(markdown).not_to include("<script>", "<img>", "![x](")
    expect(markdown).to include("&lt;script&gt;", "&#96;", "\\|")
  end

  it "exposes dedicated formats without changing JSON or SARIF documents" do
    input = manifest("demo", commands: ["/bin/tool"])
    expect(JSON.parse(Bonebed::Formatter::JSON.call([input]))).to eq([input])
    expect(JSON.parse(Bonebed::Formatter::SARIF.call([input]))).to eq(Bonebed::Sarif.call([input]))
    expect(Bonebed::Formatter::CSV.call([input])).to eq(Bonebed::CLI.format_report([input], "csv"))
    expect(Bonebed::Formatter::HTML.call([input])).to eq(Bonebed::CLI.format_report([input], "html"))
  end
end
