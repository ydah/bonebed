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
    expect(normalizer.call("/tmp/d20260909-1/build/foo.o")).to eq("$TMPDIR/<random>/build/foo.o")
    expect(normalizer.call("/proc/123/status")).to eq("/proc/<pid>/status")
    expect(normalizer.call("relative/path")).to eq("$PWD/relative/path")
    expect(normalizer.call("\0abstract")).to eq("\0abstract")
  end

  it "normalizes per-thread procfs paths" do
    expect(normalizer.call("/proc/self/task/562/comm")).to eq("/proc/<pid>/task/<tid>/comm")
    expect(normalizer.call("/proc/thread-self/task/562/comm")).to eq("/proc/<pid>/task/<tid>/comm")
    expect(normalizer.call("/proc/42/task/43/stat")).to eq("/proc/<pid>/task/<tid>/stat")
    expect(normalizer.call("/proc/42/task/43extra/stat")).to eq("/proc/<pid>/task/43extra/stat")
  end

  it "normalizes build temporary names only within their temporary and extension directories" do
    %w[c o s res cdtor.c cdtor.o].each do |suffix|
      expect(normalizer.call("/tmp/build/ccAb3dE9.#{suffix}")).to eq("$TMPDIR/<random>/cc<random>.#{suffix}")
    end
    expect(normalizer.call("/home/test/gems/gems/demo-1.0/ext/parser/.gem.20261010-22-lkwiu3/lib/parser.so"))
      .to eq("$GEM_HOME/gems/demo-1.0/ext/parser/.gem.<random>/lib/parser.so")
    expect(normalizer.call("/home/test/project/ccAb3dE9.o")).to eq("$PWD/ccAb3dE9.o")
    expect(normalizer.call("/tmp/build/ccAb3dE9.rb")).to eq("$TMPDIR/<random>/ccAb3dE9.rb")
    expect(normalizer.call("/tmp/build/compiler.o")).to eq("$TMPDIR/<random>/compiler.o")
    expect(normalizer.call("/tmp/build/source/ccAb3dE9.o")).to eq("$TMPDIR/<random>/source/ccAb3dE9.o")
    expect(normalizer.call("/home/test/gems/gems/demo-1.0/lib/.gem.20261010-22-lkwiu3/data"))
      .to eq("$GEM_HOME/gems/demo-1.0/lib/.gem.20261010-22-lkwiu3/data")
  end
end
