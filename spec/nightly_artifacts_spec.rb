# frozen_string_literal: true

require "bonebed/nightly_artifacts"

RSpec.describe Bonebed::NightlyArtifacts do
  def run(id, date)
    {"id" => id, "workflow_id" => 7, "head_repository" => {"full_name" => "owner/repo"}, "head_branch" => "main",
     "head_sha" => "a" * 40, "path" => ".github/workflows/nightly.yml", "created_at" => date, "conclusion" => "success"}
  end

  def artifacts(id)
    described_class::NAMES.map do |name|
      {"name" => name, "expired" => false, "size_in_bytes" => 100, "workflow_run" => {"id" => id, "head_sha" => "a" * 40}}
    end
  end

  it "downloads only validated artifacts from the current and previous successful same-branch workflow" do
    fetcher = described_class.new(repository: "owner/repo", run_id: "3")
    current = run(3, "2026-10-10T00:00:00Z")
    previous = run(1, "2026-10-08T00:00:00Z")
    other = run(2, "2026-10-09T00:00:00Z").merge("head_branch" => "other")
    allow(fetcher).to receive(:api).with("actions/runs/3").and_return(current)
    allow(fetcher).to receive(:api).with("actions/workflows/7/runs?status=success&per_page=100").and_return("workflow_runs" => [current, other, previous])
    [3, 1].each { |id| allow(fetcher).to receive(:api).with("actions/runs/#{id}/artifacts?per_page=100").and_return("artifacts" => artifacts(id)) }
    allow(fetcher).to receive(:gh).and_return("")
    Dir.mktmpdir do |directory|
      expect(fetcher.fetch(directory)).to include("status" => "downloaded", "previous_run" => 1)
      expect(fetcher).to have_received(:gh).with("run", "download", "1", "--repo", "owner/repo", "--name", "nightly-observations", "--dir", File.join(directory, "previous/nightly-observations"))
      expect(fetcher).to have_received(:gh).exactly(4).times
    end
  end

  it "records no history explicitly and refuses artifacts with mismatched provenance" do
    fetcher = described_class.new(repository: "owner/repo", run_id: 3)
    allow(fetcher).to receive(:api).with("actions/runs/3").and_return(run(3, "2026-10-10T00:00:00Z"))
    allow(fetcher).to receive(:api).with("actions/workflows/7/runs?status=success&per_page=100").and_return("workflow_runs" => [])
    payload = artifacts(3)
    allow(fetcher).to receive(:api).with("actions/runs/3/artifacts?per_page=100").and_return("artifacts" => payload)
    allow(fetcher).to receive(:gh).and_return("")
    Dir.mktmpdir do |directory|
      expect(fetcher.fetch(directory)).to include("status" => "no_previous", "previous_run" => nil)
      payload.first["workflow_run"]["head_sha"] = "b" * 40
      expect(fetcher.fetch(directory)).to include("status" => "error", "error" => /invalid artifact metadata/)
    end
  end

  it "compares observations from older runs without benchmarks but rejects invalid present benchmarks" do
    fetcher = described_class.new(repository: "owner/repo", run_id: 3)
    allow(fetcher).to receive(:api).with("actions/runs/3").and_return(run(3, "2026-10-10T00:00:00Z"))
    allow(fetcher).to receive(:api).with("actions/workflows/7/runs?status=success&per_page=100")
      .and_return("workflow_runs" => [run(1, "2026-10-08T00:00:00Z")])
    current_artifacts = artifacts(3)
    previous_artifacts = artifacts(1).take(1)
    allow(fetcher).to receive(:api).with("actions/runs/3/artifacts?per_page=100").and_return("artifacts" => current_artifacts)
    allow(fetcher).to receive(:api).with("actions/runs/1/artifacts?per_page=100").and_return("artifacts" => previous_artifacts)
    allow(fetcher).to receive(:gh).and_return("")
    Dir.mktmpdir do |directory|
      expect(fetcher.fetch(directory)).to include("status" => "downloaded", "previous_run" => 1, "previous_benchmark" => "no_previous_benchmark")
      expect(fetcher).to have_received(:gh).exactly(3).times
      previous_artifacts << artifacts(1).last.merge("expired" => true)
      expect(fetcher.fetch(directory)).to include("status" => "error", "error" => /invalid artifact metadata for nightly-benchmark/)
      previous_artifacts.pop
      current_artifacts.pop
      expect(fetcher.fetch(directory)).to include("status" => "error", "error" => /missing or ambiguous nightly-benchmark/)
    end
  end

  it "terminates a stalled GitHub child within its deadline" do
    fetcher = described_class.new(repository: "owner/repo", run_id: 3, timeout: 0.1)
    allow(Open3).to receive(:popen2e).with("gh", "api", pgroup: true).and_wrap_original do |method, *args, &block|
      method.call(RbConfig.ruby, "--disable-gems", "-e", "sleep 30", pgroup: true, &block)
    end
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    expect { fetcher.send(:gh, "api") }.to raise_error(Timeout::Error)
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 3
  end

  it "preserves a JSON error artifact when the comparison script cannot fetch valid inputs" do
    Dir.mktmpdir do |directory|
      destination = File.join(directory, "comparison.json")
      _out, _err, status = Open3.capture3({"GITHUB_REPOSITORY" => "invalid", "GITHUB_RUN_ID" => "3"},
        RbConfig.ruby, "-Ilib", "script/nightly_compare.rb", destination)
      expect(status.exitstatus).to eq(1)
      expect(JSON.parse(File.read(destination))).to include("fetch" => include("status" => "error", "error" => /invalid repository/))
    end
  end
end
