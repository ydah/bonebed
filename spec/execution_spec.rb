# frozen_string_literal: true

RSpec.describe "execution metadata and limits" do
  let(:normalizer) { Bonebed::PathNormalizer.new(home: "/home/test", cwd: "/app", gem_paths: ["/gems"], tmpdir: "/tmp") }

  it "keeps observer failures separate from target status through baseline subtraction" do
    collector = Bonebed::Collector.new
    collector.record_observer_error(:connect, ArgumentError.new("bad address"))
    collector.finish(Process.clock_gettime(Process::CLOCK_MONOTONIC), nil, timed_out: true)
    observation = Bonebed::Difference.call(collector.snapshot(normalizer), {files: {}})
    expect(observation[:errors]).to be_empty
    expect(observation[:observer_errors]).to eq(["connect: ArgumentError: bad address"])
    expect(observation[:target]).to eq(exit_status: nil, signal: nil, timed_out: true)
  end

  it "normalizes paths embedded in argv without changing ordinary arguments" do
    expect(normalizer.scrub("--include=/gems/demo/lib:/tmp/build123/object.o")).to eq("--include=$GEM_HOME/demo/lib:$TMPDIR/<random>/object.o")
    expect(normalizer.scrub("hello /home/test/.aws/credentials")).to eq("hello $HOME/.aws/credentials")
    expect(normalizer.scrub("/home/test-other/name")).to eq("/home/test-other/name")
    expect(normalizer.scrub("relative.rb")).to eq("relative.rb")
  end

  it "marks argv truncation only when another argument exists" do
    request = double("request", args: [100, 200])
    allow(request).to receive(:read_string).with(100).and_return("/bin/echo")
    allow(request).to receive(:read_string).with(300).and_return("echo")
    allow(request).to receive(:read).with(200, 8).and_return([300].pack("J"))
    allow(request).to receive(:read).with(208, 8).and_return([400].pack("J"))
    expect(Bonebed::Decoder::Execve.call(request, limit: 1)).to include(argv: ["echo"], argv_truncated: true)
    allow(request).to receive(:read).with(208, 8).and_return([0].pack("J"))
    expect(Bonebed::Decoder::Execve.call(request, limit: 1)).not_to include(argv_truncated: true)
  end

  it "captures a bounded prefix while draining both target output streams" do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")
    code = 'STDOUT.write("x" * 100_000); STDERR.write("y" * 32)'
    collector = nil
    expect do
      collector = Bonebed::Session.new([RbConfig.ruby, "-e", code], output_limit: 32, quiet_target: true).run
    end.to output("").to_stdout.and output("").to_stderr
    observation = collector.snapshot(normalizer)
    expect(observation).to include(stdout: "x" * 32, stderr: "y" * 32, stdout_truncated: true, stderr_truncated: false)
    expect(observation[:target]).to eq(exit_status: 0, signal: nil, timed_out: false)
    expect(observation[:started_at]).to match(/Z\z/)
  end

  it "validates limits before starting a target" do
    expect { Bonebed::Session.new(["false"], output_limit: -1) }.to raise_error(ArgumentError)
    expect { Bonebed::Session.new(["false"], argv_limit: 0) }.to raise_error(ArgumentError)
    expect { Bonebed::Session.new(["false"], resource_limits: {FSIZE: -1}) }.to raise_error(ArgumentError)
    expect { Bonebed::Dig.new(timeout: 0) }.to raise_error(ArgumentError)
  end

  it "applies hard file and descriptor limits only in the target" do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")
    parent_limit = Process.getrlimit(:NOFILE)
    Dir.mktmpdir do |directory|
      code = '$stdout.sync = true; puts Process.getrlimit(:NOFILE).join(":"); File.write("large", "x" * 8192)'
      result = Bonebed::Session.new([RbConfig.ruby, "-e", code], cwd: directory, quiet_target: true,
        resource_limits: {NOFILE: 64, FSIZE: 1024}).run.snapshot(Bonebed::PathNormalizer.new(cwd: directory))
      expect(result[:stdout]).to eq("64:64\n")
      expect(result[:errors]).not_to be_empty
      expect(File.size(File.join(directory, "large"))).to be <= 1024
      expect(Process.getrlimit(:NOFILE)).to eq(parent_limit)
    end
  end

  it "does not wait beyond the deadline for an escaped child holding output pipes" do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    collector = Bonebed::Session.new([RbConfig.ruby, "-e", "fork { Process.setsid; sleep 1 }; exit! 0"], timeout: 0.2, quiet_target: true).run
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 0.8
    expect(collector.snapshot(normalizer).dig(:target, :timed_out)).to be(true)
  end
end
