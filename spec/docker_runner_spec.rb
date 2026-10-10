# frozen_string_literal: true

require "bonebed/docker_runner"

RSpec.describe Bonebed::DockerRunner do
  it "mounts the project read-only, writes only results, and forwards literal arguments" do
    Dir.mktmpdir do |root|
      runner = described_class.new(cwd: root, image: "bonebed:test")
      command = runner.command(%w[dig demo --results output --offline])
      expect(command).to include("type=bind,source=#{root},target=/work,readonly")
      expect(command).to include("type=bind,source=#{root}/output,target=/results")
      expect(command.last(6)).to eq(%w[bonebed:test dig demo --results /results --offline])
      expect(command).to include("--read-only", "no-new-privileges", "--cap-drop", "ALL")
      expect(command).to include("/tmp:rw,exec,nosuid,nodev,size=1g,mode=1777")
      expect(command.join(" ")).not_to include("docker.sock", "GITHUB_TOKEN", "unconfined")
    end
  end

  it "rejects recursive wrappers and invalid images before launching Docker" do
    runner = described_class.new
    expect { runner.command(["--docker", "dig", "demo"]) }.to raise_error(ArgumentError)
    expect { described_class.new(image: "--privileged") }.to raise_error(ArgumentError)
    expect { runner.command([]) }.to raise_error(ArgumentError)
  end

  it "does not rewrite target arguments and rejects writable symlink mounts" do
    Dir.mktmpdir do |root|
      runner = described_class.new(cwd: root, image: "bonebed:test")
      expect(runner.command(%w[run -- echo --results literal]).last(7)).to eq(%w[run --results /results -- echo --results literal])
      expect { runner.command(%w[dig demo --results ..]) }.to raise_error(ArgumentError, /project mount/)
      expect { runner.command(%w[dig demo --results /]) }.to raise_error(ArgumentError, /project mount/)
      File.symlink("/tmp", File.join(root, "results"))
      expect { runner.command(%w[dig demo]) }.to raise_error(ArgumentError, /symlink/)
    end
  end

  it "runs Ruby versions in separate output directories and reports failures" do
    Dir.mktmpdir do |root|
      runner = described_class.new(cwd: root, ruby_image: "local:checked-ruby%{ruby}")
      calls = []
      allow(runner).to receive(:execute) do |command|
        calls << command
        command.include?("local:checked-ruby3.3") ? 1 : 2
      end
      expect { expect(runner.run(%w[run --ruby 3.3,4.0 --results observations -- ruby -e exit])).to eq(2) }.to output(/"comparisons"/).to_stdout
      expect(calls.size).to eq(2)
      %w[3.3 4.0].each_with_index do |version, index|
        expect(calls[index]).to include("local:checked-ruby#{version}")
        mount = calls[index].find { |arg| arg.end_with?("target=/results") }
        expect(mount).to match(%r{source=#{Regexp.escape(root)}/observations/ruby-matrix-[^/]+/ruby-#{version},target=/results})
        expect(calls[index].last(8)).to eq(%w[run --results /results -- ruby -e exit].unshift("local:checked-ruby#{version}"))
      end
    end
  end

  it "rejects malformed matrices before launching and leaves target Ruby flags alone" do
    runner = described_class.new
    allow(runner).to receive(:execute).and_return(0)
    [%w[run --ruby 3.3,3.3 -- true], %w[dig demo --ruby ../x], %w[report --ruby 3.3], %w[dig demo --ruby],
      %w[run --ruby 3.3 --results one --results=two -- true], %w[dig --help --ruby 3.3]].each do |args|
      expect { runner.run(args) }.to raise_error(ArgumentError)
    end
    expect(runner).not_to have_received(:execute)
    expect(runner.command(%w[run -- echo --ruby 3.3]).last(4)).to eq(%w[-- echo --ruby 3.3])
    expect { described_class.new(ruby_image: "local:latest").run(%w[dig demo --ruby 3.3]) }.to raise_error(ArgumentError, /placeholder/)
  end

  it "reports missing output as observer failure and excludes incomplete repetitions" do
    Dir.mktmpdir do |root|
      runner = described_class.new(cwd: root)
      allow(runner).to receive(:execute).and_return(0)
      expect do
        expect { expect(runner.run(%w[dig demo --ruby 3.3])).to eq(2) }.to output(/"comparisons": \[\]/).to_stdout
      end.to output(/produced no observations/).to_stderr
      manifest = JSON.parse(File.read(File.join(__dir__, "fixtures/manifest-golden/quiet.json")))
      manifest["run"]["repeat"] = {"group" => "test", "index" => 1, "count" => 2}
      manifest["stability"] = {"complete" => false}
      expect(runner.send(:matrix_observations, [manifest])).to eq({})
      manifest["stability"]["complete"] = true
      expect(runner.send(:matrix_observations, [manifest])).to eq({})
      second = Marshal.load(Marshal.dump(manifest))
      second["run"]["repeat"]["index"] = 2
      expect(runner.send(:matrix_observations, [manifest, second]).size).to eq(1)
    end
  end

  it "compares complete observations and rejects images running the wrong Ruby" do
    Dir.mktmpdir do |root|
      runner = described_class.new(cwd: root)
      mismatch = false
      allow(runner).to receive(:execute) do |command|
        version = command.find { |arg| arg.start_with?("ghcr.io/") }.split("-ruby").last
        directory = command.find { |arg| arg.end_with?("target=/results") }.split("source=", 2).last.delete_suffix(",target=/results")
        manifest = JSON.parse(File.read(File.join(__dir__, "fixtures/manifest-golden/quiet.json")))
        manifest["environment"]["ruby"] = mismatch ? "3.2.9" : "#{version}.9"
        manifest["files"]["write"] << "$PWD/new-file" if version == "4.0"
        manifest["capabilities"] = Bonebed::ResultStore.capabilities(manifest)
        Bonebed::ResultStore.new(directory).write(manifest)
        0
      end
      expect { expect(runner.run(%w[dig demo --ruby=3.3,4.0])).to eq(0) }.to output(/file:write:\$PWD\/new-file/).to_stdout
      mismatch = true
      expect do
        expect { expect(runner.run(%w[dig demo --ruby 3.3,4.0])).to eq(2) }.to output(/"comparisons": \[\]/).to_stdout
      end.to output(/Ruby image mismatch/).to_stderr
      expect(Dir[File.join(root, "results", "ruby-matrix-*")].size).to eq(2)
    end
  end
end
