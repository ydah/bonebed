# frozen_string_literal: true

require "bonebed/decoder/file_change"
require "bonebed/syscalls"

RSpec.describe Bonebed::Decoder::FileChange do
  def request(args, paths)
    double("request", args:, pid: 42).tap do |request|
      allow(request).to receive(:read_string) { |address| paths.fetch(address) }
    end
  end

  it "resolves both renameat paths against their own directory descriptors" do
    target = request([7, 100, 8, 200, 0], 100 => "old", 200 => "new")
    allow(File).to receive(:readlink).with("/proc/42/fd/7").and_return("/source")
    allow(File).to receive(:readlink).with("/proc/42/fd/8").and_return("/destination")
    expect(described_class.call(target, syscall: :renameat2)).to eq(operation: :rename, from: "/source/old", to: "/destination/new")
  end

  it "keeps symbolic link contents relative to the created link" do
    target = request([100, 7, 200], 100 => "../target", 200 => "link")
    allow(File).to receive(:readlink).with("/proc/42/fd/7").and_return("/links")
    expect(described_class.call(target, syscall: :symlinkat)).to eq(operation: :link, from: "../target", to: "/links/link", symbolic: true)
  end

  it "records file permissions, ownership, deletion and directory creation" do
    expect(described_class.call(request([-100, 100, 0o755], 100 => "/app/hook"), syscall: :fchmodat)).to eq(operation: :chmod, path: "/app/hook", mode: 0o755)
    expect(described_class.call(request([100, 123, 456], 100 => "/app/file"), syscall: :chown)).to eq(operation: :chown, path: "/app/file", uid: 123, gid: 456)
    expect(described_class.call(request([100], 100 => "/app/file"), syscall: :unlink)).to eq(operation: :delete, path: "/app/file")
    expect(described_class.call(request([-100, 100, 0o700], 100 => "/app/private"), syscall: :mkdirat)).to eq(operation: :mkdir, path: "/app/private", mode: 0o700)
  end

  it "resolves legacy relative paths and descriptor-based chmod" do
    allow(File).to receive(:readlink).with("/proc/42/cwd").and_raise(Errno::ENOENT)
    expect(described_class.call(request([100], 100 => "file"), syscall: :unlink, cwd: "/app")).to eq(operation: :delete, path: "/app/file")
    allow(File).to receive(:readlink).with("/proc/42/fd/7").and_return("/app/file")
    expect(described_class.call(request([7, 0o600], {}), syscall: :fchmod)).to eq(operation: :chmod, path: "/app/file", mode: 0o600)
    expect(described_class.call(request([7, 4], {}), syscall: :ftruncate)).to eq(operation: :truncate, path: "/app/file", length: 4)
    expect(described_class.call(request([100, 0], 100 => "/app/file"), syscall: :truncate)).to eq(operation: :truncate, path: "/app/file", length: 0)
  end
end

RSpec.describe Bonebed::Syscalls do
  it "only lists names present in each supported seccomp syscall table" do
    require "seccomp/notify"
    %i[x86_64 aarch64].each do |arch|
      names = described_class.file_changes(arch) + described_class::SUSPICIOUS + described_class::DATAGRAMS
      expect(names - Seccomp::Notify::Syscalls::TABLES.fetch(arch).keys).to be_empty
    end
    expect(described_class.file_changes(:aarch64)).not_to include(:unlink, :rename, :creat)
    expect(described_class.file_changes(:x86_64)).to include(:unlink, :rename, :creat)
  end
end
