# frozen_string_literal: true

RSpec.describe Bonebed::Doctor do
  describe ".container?" do
    before do
      allow(File).to receive(:exist?).and_call_original
      allow(File).to receive(:exist?).with("/.dockerenv").and_return(false)
      allow(File).to receive(:exist?).with("/run/.containerenv").and_return(false)
      allow(File).to receive(:read).with("/proc/1/cgroup").and_return("0::/\n")
    end

    it "recognizes Docker and Podman marker files" do
      allow(File).to receive(:exist?).with("/.dockerenv").and_return(true)
      expect(described_class.container?).to be(true)
      allow(File).to receive(:exist?).with("/.dockerenv").and_return(false)
      allow(File).to receive(:exist?).with("/run/.containerenv").and_return(true)
      expect(described_class.container?).to be(true)
    end

    it "recognizes container cgroups" do
      allow(File).to receive(:read).with("/proc/1/cgroup").and_return("0::/kubepods.slice/containerd-123.scope\n")
      expect(described_class.container?).to be(true)
    end

    it "handles missing procfs and ordinary host cgroups" do
      expect(described_class.container?).to be(false)
      allow(File).to receive(:read).with("/proc/1/cgroup").and_raise(Errno::ENOENT)
      expect(described_class.container?).to be(false)
    end
  end

  it "reports runtime and optional isolation prerequisites without requiring them" do
    output = StringIO.new
    doctor = described_class.new(output:)
    allow(doctor).to receive(:linux?).and_return(true)
    allow(doctor).to receive(:kernel_release).and_return("6.8.0")
    allow(doctor).to receive(:arch).and_return("x86_64")
    allow(doctor).to receive(:seccomp_features).and_return(user_notif: true, continue: true, addfd: true)
    expect(doctor.run).to be(true)
    expect(output.string).to include("Ruby", "RubyGems", "Bundler", "user namespaces", "AppArmor userns restriction", "cgroup v2", "container (heuristic)")
  end
end
