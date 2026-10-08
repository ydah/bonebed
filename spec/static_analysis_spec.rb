# frozen_string_literal: true

require "bonebed/cli"
require "bonebed/static_analysis"
require "tmpdir"

RSpec.describe Bonebed::StaticAnalysis do
  before do |example|
    skip "Prism is optional on this Ruby" if example.metadata[:prism] && !described_class.prism_available?
  end
  around do |example|
    Dir.mktmpdir("bonebed-static-") { |root| Dir.chdir(root) { example.run } }
  end

  it "finds AST calls and locations without executing source or matching comments and strings", :prism do
    File.write("source.rb", <<~SOURCE)
      # system("comment")
      "eval('a string')"
      File.write("executed", "never")
      system("curl", "https://example.test")
      Kernel.exec("/usr/bin/id")
      Process.spawn("echo", "hello")
      `uname -a`
      eval("1 + 1")
      Net::HTTP.get(URI("https://example.test"))
      Socket.new(Socket::AF_INET, Socket::SOCK_STREAM)
    SOURCE
    result = described_class.call("source.rb")
    expect(result.fetch("available")).to be(true)
    expect(result.fetch("errors")).to eq([])
    signals = result.fetch("signals")
    expect(signals.map { |signal| signal.fetch("line") }).to eq((4..10).to_a)
    expect(signals.map { |signal| signal.fetch("kind") }).to eq(%w[exec exec exec exec eval network network])
    expect(signals.first).to include("file" => "source.rb", "call" => "system", "literal" => "curl", "observed" => nil)
    expect(File.exist?("executed")).to be(false)
  end

  it "compares literal commands to observations without treating unrelated commands as observed", :prism do
    File.write("source.rb", "system('curl')\nspawn('wget')\neval('1')\nNet::HTTP.get('example.test', '/')\n")
    manifest = {"exec" => [{"path" => "/usr/bin/curl"}], "sockets" => [{"family" => "AF_INET", "type" => 1, "protocol" => 0}]}
    result = described_class.call("source.rb", manifest:)
    expect(result.fetch("signals").map { |signal| signal["observed"] }).to eq([true, false, nil, true])
    expect(result.fetch("notes").join).to include("does not prove")
  end

  it "reports parse errors and scans nested Ruby files deterministically", :prism do
    Dir.mkdir("lib")
    File.write("lib/b.rb", "system('b')")
    File.write("lib/a.rb", "def broken(")
    File.write("lib/ignored.txt", "system('ignored')")
    result = described_class.call("lib")
    expect(result.fetch("errors").first).to include("file" => "a.rb", "line" => 1)
    expect(result.fetch("signals").map { |signal| signal["file"] }).to eq(["b.rb"])
  end

  it "reports unavailable Prism without executing code" do
    File.write("source.rb", "abort 'never'")
    allow(described_class).to receive(:prism_available?).and_return(false)
    expect(described_class.call("source.rb")).to include("available" => false, "signals" => [], "reason" => /Prism/)
    expect { expect(Bonebed::CLI.static(["source.rb"])).to eq(2) }.to output(/unavailable/).to_stdout
  end

  it "does not follow source symlinks outside the requested directory", :prism do
    Dir.mkdir("lib")
    File.write("outside.rb", "system('outside')")
    File.symlink(File.expand_path("outside.rb"), "lib/link.rb")
    expect(described_class.call("lib").fetch("signals")).to eq([])
  end

  it "exposes static JSON and reports syntax errors with status one", :prism do
    File.write("source.rb", "def broken(")
    expect { expect(Bonebed::CLI.static(["source.rb"])).to eq(1) }.to output(/errors/).to_stdout
  end
end
