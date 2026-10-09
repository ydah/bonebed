# frozen_string_literal: true

RSpec.describe "session trace and process lifetime" do
  before { skip "Linux seccomp and procfs are required" unless RUBY_PLATFORM.include?("linux") }

  it "records unavailable cgroup delegation without failing an ordinary observation" do
    allow(Bonebed::Cgroup).to receive(:create).and_raise(Bonebed::Cgroup::Unavailable, "fixture read-only delegation")
    collector = Bonebed::Session.new([RbConfig.ruby, "-e", ""], quiet_target: true).run
    snapshot = collector.snapshot(Bonebed::PathNormalizer.new)
    expect(snapshot[:errors]).to be_empty
    expect(snapshot[:observer_errors]).to be_empty
    expect(snapshot[:cleanup]).to include("mode" => "tracked", "limitation" => include("fixture read-only delegation"))
  end

  it "holds the target before exec until cgroup attachment succeeds" do
    Dir.mktmpdir do |root|
      marker = File.join(root, "executed")
      group = double("cgroup", kill: Bonebed::Cgroup::Result.new(processes: {}, errors: []), close: [])
      expect(group).to receive(:close).once.and_return([])
      allow(Bonebed::Cgroup).to receive(:create).and_return(group)
      expect(group).to receive(:attach) do |pid|
        expect(Bonebed::Isolation.process_info(pid).fetch(:parent)).to eq(Process.pid)
        sleep 0.05
        expect(File).not_to exist(marker)
      end
      collector = Bonebed::Session.new([RbConfig.ruby, "-e", 'File.write(ARGV.first, "yes")', marker], quiet_target: true).run
      expect(collector.errors).to be_empty
      expect(File).to exist(marker)
      expect(collector.snapshot(Bonebed::PathNormalizer.new)[:cleanup]).to include("mode" => "cgroup_v2", "completed" => true)
    end
  end

  it "releases the child into tracked cleanup when cgroup attachment is unavailable" do
    group = double("cgroup", kill: Bonebed::Cgroup::Result.new(processes: {}, errors: []), close: [])
    allow(group).to receive(:attach).and_raise(Bonebed::Cgroup::Unavailable, "fixture attachment rejected")
    allow(Bonebed::Cgroup).to receive(:create).and_return(group)
    collector = Bonebed::Session.new([RbConfig.ruby, "-e", 'puts "executed"'], quiet_target: true).run
    snapshot = collector.snapshot(Bonebed::PathNormalizer.new)
    expect(snapshot[:errors]).to be_empty
    expect(snapshot[:stdout]).to include("executed")
    expect(snapshot[:cleanup]).to include("mode" => "tracked", "limitation" => include("attachment rejected"))
  end

  it "reaps the waiting target if cgroup attachment is interrupted" do
    group = double("cgroup", kill: Bonebed::Cgroup::Result.new(processes: {}, errors: []), close: [])
    allow(Bonebed::Cgroup).to receive(:create).and_return(group)
    pid = nil
    allow(group).to receive(:attach) do |target|
      pid = target
      raise Interrupt
    end
    descriptors = Dir["/proc/self/fd/*"].size
    expect { Bonebed::Session.new([RbConfig.ruby, "-e", "sleep 30"], quiet_target: true).run }.to raise_error(Interrupt)
    expect { Process.waitpid(pid, Process::WNOHANG) }.to raise_error(Errno::ECHILD)
    expect { Process.kill(0, pid) }.to raise_error(Errno::ESRCH)
    expect(Dir["/proc/self/fd/*"].size).to eq(descriptors)
  end

  it "writes decoded normalized JSONL events and links execs to their parent executable" do
    Dir.mktmpdir do |root|
      trace = File.join(root, "trace.jsonl")
      code = 'system(ARGV.fetch(0), "-e", %q{File.write("created", "fixture")}) or abort "child failed"'
      collector = Bonebed::Session.new([RbConfig.ruby, "-e", code, RbConfig.ruby], cwd: root, trace:,
        env: {"TRACE_SECRET" => "do-not-log-this-value"}).run
      observation = collector.snapshot(Bonebed::PathNormalizer.new(cwd: root))
      rows = File.readlines(trace).map { |line| JSON.parse(line) }

      expect(observation[:errors]).to be_empty
      expect(observation[:observer_errors]).to be_empty
      expect(rows).to include(include("syscall" => "openat", "path" => "$PWD/created"))
      expect(rows).to all(include("t" => a_kind_of(Numeric), "tid" => a_kind_of(Integer), "tgid" => a_kind_of(Integer), "ppid" => a_kind_of(Integer)))
      expect(File.read(trace)).not_to include("do-not-log-this-value")
      expect(rows).to include(include("syscall" => "execve", "env_keys" => include("TRACE_SECRET")))
      expect(observation[:exec].keys).to include(include(parent: File.realpath(RbConfig.ruby)))
      expect(observation.fetch(:process_tree)).to include(include(path: File.realpath(RbConfig.ruby), parent: File.realpath(RbConfig.ruby)))
    end
  end

  it "reaps detached descendants as the root exits without killing unrelated children" do
    Dir.mktmpdir do |root|
      unrelated = Process.fork { sleep 30 }
      code = <<~RUBY
        first = fork do
          Process.setsid
          fork do
            File.write("daemon.pid", Process.pid.to_s)
            sleep 0.6
            File.write("survived", "unexpected")
            exit! 0
          end
          exit! 0
        end
        Process.wait(first)
        sleep 0.01 until File.exist?("daemon.pid")
      RUBY
      collector = Bonebed::Session.new([RbConfig.ruby, "-e", code], cwd: root, timeout: 3).run
      daemon = Integer(File.read(File.join(root, "daemon.pid")))
      sleep 0.7

      expect(collector.errors).to be_empty
      expect(collector.observer_errors).to be_empty
      expect(File.exist?(File.join(root, "survived"))).to be(false)
      expect { Process.kill(0, daemon) }.to raise_error(Errno::ESRCH)
      expect { Process.waitpid(daemon, Process::WNOHANG) }.to raise_error(Errno::ECHILD)
      expect(Process.kill(0, unrelated)).to eq(1)
      expect(Process.waitpid(unrelated, Process::WNOHANG)).to be_nil
    ensure
      begin
        Process.kill("KILL", unrelated) if unrelated
        Process.waitpid(unrelated) if unrelated
      rescue Errno::ESRCH, Errno::ECHILD
        nil
      end
    end
  end

  it "normalizes datagram paths and redacts canaries before writing trace rows" do
    Bonebed::GemEnvironment.open do |environment|
      trace = File.join(environment.root, "trace.jsonl")
      code = <<~RUBY
        require "socket"
        require "rbconfig"
        receiver = Socket.new(Socket::AF_UNIX, Socket::SOCK_DGRAM, 0)
        address = Socket.sockaddr_un(File.expand_path("receiver"))
        receiver.bind(address)
        Socket.new(Socket::AF_UNIX, Socket::SOCK_DGRAM, 0).send("fixture", 0, address)
        system(RbConfig.ruby, "-e", "", ENV.fetch("GITHUB_TOKEN")) or abort "child failed"
      RUBY
      result = Bonebed::Session.new([RbConfig.ruby, "-e", code], env: environment.env, cwd: environment.project,
        quiet_target: true, unsetenv_others: true, trace:, redactor: environment.honeypot).run
      expect(result.errors).to be_empty
      text = File.read(trace)
      expect(text).not_to include(environment.env.fetch("GITHUB_TOKEN"))
      expect(text).to include("[CANARY:env:GITHUB_TOKEN]")
      rows = text.lines.map { |line| JSON.parse(line) }
      expect(rows).to include(include("messages" => include(include("path" => "$PWD/receiver"))))
    end
  end

  it "fails closed before executing the target when requested enforcement is unavailable" do
    allow(Bonebed::Landlock).to receive(:restrict!).and_raise(Bonebed::Landlock::Unavailable, "fixture enforcement unavailable")
    collector = Bonebed::Session.new([RbConfig.ruby, "-e", 'puts "target executed"'], quiet_target: true,
      enforcement: {read_paths: [], write_paths: []}).run
    observation = collector.snapshot(Bonebed::PathNormalizer.new)

    expect(observation.dig(:target, :exit_status)).to eq(126)
    expect(observation[:stderr]).to include("fixture enforcement unavailable")
    expect(observation[:stdout]).to be_empty
  end
end
