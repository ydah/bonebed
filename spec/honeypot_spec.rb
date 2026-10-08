# frozen_string_literal: true

require "bonebed/honeypot"

RSpec.describe Bonebed::Honeypot do
  it "creates distinct fake credentials and detects their actual exposed values" do
    Dir.mktmpdir do |root|
      home = File.join(root, "home")
      project = File.join(root, "project")
      honeypot = described_class.new(home:, project:)
      aws = File.read(File.join(home, ".aws/credentials"))
      access_key = aws[/aws_access_key_id = (.+)/, 1]
      secret_key = aws[/aws_secret_access_key = (.+)/, 1]
      master_key = File.read(File.join(project, "config/master.key"))
      expect(access_key).to match(/\AAKIA[A-F0-9]{16}\z/)
      expect(master_key.length).to eq(32)
      expect(honeypot.env.values.uniq.length).to eq(honeypot.env.length)
      manifest = {"stdout" => access_key, "stderr" => master_key,
                  "exec" => [{"argv" => [secret_key, honeypot.env.fetch("GITHUB_TOKEN")]}],
                  "files" => {"read" => ["/tmp/#{secret_key}"]}}

      redacted = honeypot.redact(manifest)

      [access_key, secret_key, master_key, *honeypot.env.values].each do |token|
        expect(JSON.generate(redacted)).not_to include(token)
      end
      expect(redacted.fetch("canary_hits")).to include(
        {"source" => ".aws/credentials", "seen_in" => "stdout"},
        {"source" => ".aws/credentials", "seen_in" => "exec"},
        {"source" => "config/master.key", "seen_in" => "stderr"},
        {"source" => "env:GITHUB_TOKEN", "seen_in" => "exec"}
      )
      expect(manifest.fetch("stdout")).to eq(access_key)
      expect(File.stat(File.join(home, ".ssh/id_ed25519")).mode & 0o777).to eq(0o600)
    end
  end

  it "redacts nested hash keys and deduplicates repeated hits" do
    Dir.mktmpdir do |root|
      honeypot = described_class.new(home: root, project: nil)
      token = honeypot.env.fetch("AWS_ACCESS_KEY_ID")
      result = honeypot.redact({"dns" => [{token => "#{token}.example.invalid"}, token]})

      expect(JSON.generate(result)).not_to include(token)
      expect(result.fetch("canary_hits")).to eq([{"source" => "env:AWS_ACCESS_KEY_ID", "seen_in" => "dns"}])
      expect(File.exist?(File.join(root, "Gemfile"))).to be(false)
    end
  end
end
