# frozen_string_literal: true

RSpec.describe Bonebed::PathNormalizer do
  subject(:normalizer) do
    described_class.new(home: "/home/test", gem_paths: ["/home/test/gems"], tmpdir: "/tmp", cwd: "/home/test/project")
  end

  it "normalizes environment-specific path prefixes" do
    expect(normalizer.call("/home/test/gems/foo/lib/foo.rb")).to eq("$GEM_HOME/foo/lib/foo.rb")
    expect(normalizer.call("/home/test/project/log/demo.log")).to eq("$PWD/log/demo.log")
    expect(normalizer.call("/home/test/.gitconfig")).to eq("$HOME/.gitconfig")
    expect(normalizer.call("/tmp/d20260909-1")).to eq("$TMPDIR/<random>")
    expect(normalizer.call("/proc/123/status")).to eq("/proc/<pid>/status")
    expect(normalizer.call("relative/path")).to eq("relative/path")
  end
end
