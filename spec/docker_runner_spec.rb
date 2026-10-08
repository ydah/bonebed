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
      File.symlink("/tmp", File.join(root, "results"))
      expect { runner.command(%w[dig demo]) }.to raise_error(ArgumentError, /symlink/)
    end
  end
end
