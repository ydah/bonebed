# frozen_string_literal: true

require "bonebed/cgroup"

RSpec.describe Bonebed::Cgroup do
  around do |example|
    Dir.mktmpdir("cgroup-fixture-") do |root|
      @root = root
      File.write(File.join(root, "cgroup.controllers"), "")
      File.write(File.join(root, "cgroup.procs"), Process.pid.to_s)
      File.write(File.join(root, "cgroup.kill"), "ancestor must remain untouched")
      example.run
    end
  end

  before do
    allow(Dir).to receive(:mkdir).and_wrap_original do |original, path, *arguments|
      original.call(path, *arguments)
      if File.dirname(path) == @root
        {"cgroup.type" => "domain", "cgroup.events" => "populated 0\nfrozen 1\n",
         "cgroup.procs" => "", "cgroup.kill" => "", "cgroup.freeze" => ""}.each do |name, contents|
          File.write(File.join(path, name), contents)
        end
      end
    end
  end

  it "resolves the current delegated cgroup beneath its v2 mount" do
    membership = "0::/user.slice/session.scope\n"
    mounts = "20 19 0:30 /user.slice /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
    expect(described_class.delegated_directory(membership:, mounts:)).to eq("/sys/fs/cgroup/session.scope")
    expect { described_class.delegated_directory(membership: "0::/../escape\n", mounts:) }.to raise_error(described_class::Unavailable)
    expect { described_class.delegated_directory(membership:, mounts: "") }.to raise_error(described_class::Unavailable)
  end

  it "attaches only a direct child to a new dedicated group and kills only that group" do
    group = described_class.create(parent: @root)
    allow(Bonebed::Isolation).to receive(:process_info).with(12345).and_return(parent: Process.pid, started_at: 42)
    group.attach(12345)
    expect(File.read(File.join(group.path, "cgroup.procs"))).to eq("12345")
    result = group.kill(timeout: 0.05)
    expect(result.errors).to be_empty
    expect(result.processes).to eq(12345 => 42)
    expect(File.read(File.join(group.path, "cgroup.kill"))).to eq("1")
    expect(File.read(File.join(@root, "cgroup.kill"))).to eq("ancestor must remain untouched")
    expect { group.attach(Process.pid) }.to raise_error(described_class::Unavailable)
  ensure
    group&.close
  end

  it "bounds waiting for populated zero and reports an incomplete cleanup" do
    group = described_class.create(parent: @root)
    File.write(File.join(group.path, "cgroup.events"), "populated 1\nfrozen 1\n")
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result = group.kill(timeout: 0.03)
    expect(result.errors.join).to include("populated")
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 0.3
  ensure
    group&.close
  end

  it "retries cleanup interrupted before the kill instead of caching success" do
    group = described_class.create(parent: @root)
    interrupted = false
    allow(group).to receive(:collect_processes).and_wrap_original do |original, *arguments|
      unless interrupted
        interrupted = true
        raise Timeout::Error, "outer session deadline"
      end
      original.call(*arguments)
    end
    expect { group.kill(timeout: 0.05) }.to raise_error(Timeout::Error)
    expect(File.read(File.join(group.path, "cgroup.kill"))).to eq("")
    expect(group.kill(timeout: 0.05).errors).to be_empty
    expect(File.read(File.join(group.path, "cgroup.kill"))).to eq("1")
  ensure
    group&.close
  end

  it "retries interruption while waiting for an empty group" do
    group = described_class.create(parent: @root)
    allow(Bonebed::Isolation).to receive(:process_info).with(12345).and_return(parent: Process.pid, started_at: 42)
    group.attach(12345)
    File.write(File.join(group.path, "cgroup.events"), "populated 1\nfrozen 1\n")
    expect { Timeout.timeout(0.02) { group.kill(timeout: 1) } }.to raise_error(Timeout::Error)
    File.write(File.join(group.path, "cgroup.procs"), "")
    result = group.kill(timeout: 0.02)
    expect(result.errors.join).to include("populated")
    expect(result.processes).to eq(12345 => 42)
    expect(File.read(File.join(group.path, "cgroup.kill"))).to eq("1")
  ensure
    group&.close
  end

  it "does not freeze or kill a group containing the supervisor" do
    group = described_class.create(parent: @root)
    File.write(File.join(group.path, "cgroup.procs"), Process.pid.to_s)
    expect(group.kill(timeout: 0.05).errors.join).to include("supervisor")
    expect(File.read(File.join(group.path, "cgroup.freeze"))).to eq("")
    expect(File.read(File.join(group.path, "cgroup.kill"))).to eq("")
  ensure
    group&.close
  end

  it "uses pinned control files after its directory is renamed" do
    group = described_class.create(parent: @root)
    previous = group.path
    moved = "#{previous}-moved"
    File.rename(previous, moved)
    Dir.mkdir(previous)
    File.write(File.join(previous, "cgroup.kill"), "replacement must remain untouched")
    expect(group.kill(timeout: 0.05).errors).to be_empty
    expect(File.read(File.join(previous, "cgroup.kill"))).to eq("replacement must remain untouched")
    expect(File.read(File.join(moved, "cgroup.kill"))).to eq("1")
    expect(group.close.join).to include("replaced")
    expect(File).to be_directory(previous)
  end

  it "removes only empty descendant directories from its pinned subtree" do
    group = described_class.create(parent: @root)
    expect(group.kill(timeout: 0.05).errors).to be_empty
    child = File.join(group.path, "child")
    Dir.mkdir(child)
    Dir.mkdir(File.join(child, "grandchild"))
    group.close
    expect(File).not_to be_directory(child)
    expect(File.read(File.join(group.path, "cgroup.kill"))).to eq("1")
    expect(File.read(File.join(@root, "cgroup.kill"))).to eq("ancestor must remain untouched")
  ensure
    group&.close
  end

  it "does not follow a symlink while removing descendant groups" do
    group = described_class.create(parent: @root)
    expect(group.kill(timeout: 0.05).errors).to be_empty
    other = File.join(@root, "other")
    Dir.mkdir(other)
    File.symlink(other, File.join(group.path, "escape"))
    expect(group.close.join).to include("symlink")
    expect(File).to be_directory(other)
  ensure
    group&.close
  end

  it "kills a real delegated group when the environment provides one" do
    begin
      group = described_class.create
    rescue described_class::Unavailable => error
      skip error.message
    end
    Bonebed::Isolation.subreaper!
    reader, writer = IO.pipe
    pid = Process.fork do
      writer.close
      reader.read(1)
      fork {
        Process.setsid
        sleep 30
      }
      sleep 30
    end
    reader.close
    group.attach(pid)
    writer.write("1")
    writer.close
    sleep 0.05
    result = group.kill(timeout: 1)
    expect(result.errors).to be_empty
    expect(Process.waitpid(pid)).to eq(pid)
    Bonebed::Isolation.cleanup(result.processes.except(pid))
  ensure
    reader&.close unless reader&.closed?
    writer&.close unless writer&.closed?
    cleanup = group&.kill(timeout: 1)
    Bonebed::Isolation.cleanup(cleanup.processes) if cleanup
    group&.close
  end
end
