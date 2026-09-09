# frozen_string_literal: true

RSpec.describe Bonebed::Difference do
  it "subtracts baseline event counts without changing observed totals" do
    observed = {
      files: {read: {"ruby.rb" => 2, "gem.rb" => 1}, write: {}},
      network: {{family: "inet", addr: "127.0.0.1", port: 443} => 2},
      exec: {{path: "/usr/bin/git", argv: ["git"]} => 1},
      stats: {openat_total: 3, notify_roundtrips: 6, wall_ms: 10},
      errors: []
    }
    baseline = {
      files: {read: {"ruby.rb" => 2}, write: {}},
      network: {{family: "inet", addr: "127.0.0.1", port: 443} => 1},
      exec: {}
    }

    result = described_class.call(observed, baseline)

    expect(result.dig(:files, :read)).to eq("gem.rb" => 1)
    expect(result[:network].values).to eq([1])
    expect(result[:exec].values).to eq([1])
    expect(result[:stats]).to include(openat_total: 3, openat_after_baseline: 1)
  end
end
