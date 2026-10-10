# frozen_string_literal: true

RSpec.describe "Signals sent to other processes" do
  before { skip "Linux seccomp required" unless RUBY_PLATFORM.include?("linux") }

  def observe(code, *arguments, **options)
    Bonebed::Session.new([RbConfig.ruby, "-e", code, *arguments.map(&:to_s)], quiet_target: true, **options).run
      .snapshot(Bonebed::PathNormalizer.new)
  end

  def with_external_process
    pid = Process.spawn(RbConfig.ruby, "-e", "sleep 30", out: File::NULL, err: File::NULL)
    yield pid
  ensure
    if pid
      begin
        Process.kill("TERM", pid)
        Process.waitpid(pid)
      rescue Errno::ESRCH, Errno::ECHILD
        nil
      end
    end
  end

  it "records real signals to a test-owned external process with normalized destination IDs" do
    with_external_process do |pid|
      result = observe('Process.kill("CONT", Integer(ARGV.first))', pid)
      expect(result[:errors]).to be_empty
      expect(result[:observer_errors]).to be_empty
      expect(result[:suspicious]).to include({syscall: "kill", signal: Signal.list.fetch("CONT"), target_pid: "<pid>"} => 1)
      expect(Process.waitpid(pid, Process::WNOHANG)).to be_nil
    end
  end

  it "excludes signals to the caller process or another thread of that same process" do
    result = observe('Process.kill("CONT", Process.pid); Thread.new { Process.kill("CONT", Thread.current.native_thread_id) }.join')
    expect(result[:errors]).to be_empty
    expect(result[:observer_errors]).to be_empty
    expect(result[:suspicious].keys).not_to include(include(syscall: "kill"))
  end

  it "records zero and negative process-group destinations without exposing unstable IDs" do
    result = observe('Process.kill("CONT", 0); Process.kill("CONT", -Process.getpgrp)')
    expect(result[:errors]).to be_empty
    expect(result[:observer_errors]).to be_empty
    targets = result[:suspicious].keys.select { |event| event[:syscall] == "kill" }.map { |event| event[:target_pid] }
    expect(targets).to contain_exactly("current_process_group", "<pgid>")
  end

  it "records signal-zero existence probes only in trace output" do
    Dir.mktmpdir do |root|
      trace = File.join(root, "trace.jsonl")
      result = observe("Process.kill(0, Process.ppid); begin; Process.kill(0, -1); rescue Errno::ESRCH; end", trace:)
      expect(result[:errors]).to be_empty
      expect(result[:observer_errors]).to be_empty
      expect(result[:suspicious].keys).not_to include(include(syscall: "kill"))
      calls = File.readlines(trace).map { |line| JSON.parse(line) }.select { |entry| entry["syscall"] == "kill" }
      expect(calls.size).to eq(2)
      expect(calls).to all(include("signal" => 0, "probe" => true))
      expect(calls.last["target_pid"]).to eq(-1)
    end
  end

  it "allows an explicit custom policy to refuse external signals without blocking self signals" do
    with_external_process do |pid|
      config = {"rules" => {"custom" => [{"id" => "external-signal", "severity" => "high", "match" => ["syscall:kill"]}]}}
      deny = Bonebed::DenyPolicy.context(config, name: "command", phase: "exec")
      code = 'Process.kill("CONT", Process.pid); begin; Process.kill("CONT", Integer(ARGV.first)); abort "allowed"; rescue Errno::EPERM; puts "denied"; end'
      result = observe(code, pid, deny:)
      expect(result[:stdout]).to eq("denied\n")
      expect(result[:errors]).to be_empty
      expect(result[:denied].keys).to include(include(capability: "syscall:kill", rule_id: "external-signal"))
    end
  end
end
