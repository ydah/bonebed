# frozen_string_literal: true

require "tempfile"

RSpec.describe Bonebed::Survey do
  it "continues after target errors and reports failure" do
    dig = instance_double(Bonebed::Dig, result_exists?: false, last_observer_errors: [], run: nil)
    allow(dig).to receive(:last_errors).and_return([], ["failed"])
    entries = [{name: "rake", version: nil}, {name: "json", version: nil}]

    expect(described_class.new(dig:, output: StringIO.new).run(entries, phase: "require")).to be(false)
    expect(dig).to have_received(:run).twice
  end

  it "continues after a missing gem and records its failure" do
    error = Gem::LoadError.new("missing gem")
    dig = instance_double(Bonebed::Dig, result_exists?: false, last_observer_errors: [], run: nil, last_errors: [], write_failure: nil)
    allow(dig).to receive(:run).with("missing", phase: "require", version: nil, require_path: nil).and_raise(error)
    entries = [{name: "missing", version: nil}, {name: "rake", version: nil}]

    expect(described_class.new(dig:, output: StringIO.new).run(entries, phase: "require")).to be(false)
    expect(dig).to have_received(:run).twice
    expect(dig).to have_received(:write_failure).with("missing", phase: "require", version: "unknown", error:)
  end

  it "passes an entry's require path to dig" do
    dig = instance_double(Bonebed::Dig, result_exists?: false, last_observer_errors: [], run: nil, last_errors: [])
    entry = {name: "sinatra", version: nil, require_path: "sinatra/base"}

    expect(described_class.new(dig:, output: StringIO.new).run([entry], phase: "require")).to be(true)
    expect(dig).to have_received(:run).with("sinatra", phase: "require", version: nil, require_path: "sinatra/base")
  end

  it "reclaims unreachable objects after every survey entry" do
    dig = instance_double(Bonebed::Dig, result_exists?: false, last_observer_errors: [], run: nil, last_errors: [])
    allow(GC).to receive(:start)

    described_class.new(dig:, output: StringIO.new).run([{name: "rake"}, {name: "json"}], phase: "require")

    expect(GC).to have_received(:start).twice
  end

  it "runs isolated survey entries in fresh processes" do
    file = Tempfile.new
    path = file.path
    file.close
    dig = Object.new
    dig.define_singleton_method(:result_exists?) { |*| false }
    dig.define_singleton_method(:run) do |*|
      File.open(path, "a") { |output| output.puts(Process.pid) }
      @last_errors = []
    end
    dig.define_singleton_method(:last_errors) { @last_errors }
    dig.define_singleton_method(:last_observer_errors) { ["observer warning"] }

    expect(described_class.new(dig:, output: StringIO.new, isolate: true).run([{name: "rake"}, {name: "json"}], phase: "require")).to be(true)
    expect(File.readlines(path, chomp: true).map(&:to_i)).to all(satisfy { |pid| pid != Process.pid })
  ensure
    file&.unlink
  end

  it "continues after an isolated worker is killed" do
    file = Tempfile.new
    path = file.path
    file.close
    dig = Object.new
    dig.define_singleton_method(:result_exists?) { |*| false }
    dig.define_singleton_method(:run) do |name, **|
      Process.kill("KILL", Process.pid) if name == "killed"
      File.open(path, "a") { |output| output.puts(name) }
      @last_errors = []
    end
    dig.define_singleton_method(:last_errors) { @last_errors }
    dig.define_singleton_method(:last_observer_errors) { ["observer warning"] }
    dig.define_singleton_method(:write_failure) { |*| nil }
    entries = [{name: "killed"}, {name: "continued"}]

    expect(described_class.new(dig:, output: StringIO.new, isolate: true).run(entries, phase: "require")).to be(false)
    expect(File.read(path)).to eq("continued\n")
  ensure
    file&.unlink
  end

  it "extracts unique gem names from the official stats pages" do
    html = '<a href="/gems/rake">rake</a><a href="/gems/json?locale=en">json</a><a href="/gems/rake">rake</a>'

    expect(described_class.send(:names_from, html)).to eq(%w[rake json rake])
  end

  it "runs bounded parallel workers and combines observer errors" do
    Dir.mktmpdir do |root|
      log = File.join(root, "workers")
      dig = parallel_dig(log)
      prepared = []
      dig.define_singleton_method(:prepare_baselines) { |phase:| prepared << [phase, Process.pid] }
      survey = described_class.new(dig:, output: StringIO.new, jobs: 2)
      entries = %w[one two three four].map { |name| {name:} }

      expect(survey.run(entries, phase: "require")).to be(true)

      expect(prepared).to eq([["require", Process.pid]])
      expect(survey.last_observer_errors).to contain_exactly("one warning", "two warning", "three warning", "four warning")
      active = maximum = 0
      pids = []
      File.readlines(log, chomp: true).each do |line|
        event, pid = line.split
        active += (event == "start") ? 1 : -1
        maximum = [maximum, active].max
        pids << pid.to_i
      end
      expect(maximum).to eq(2)
      expect(active).to eq(0)
      expect(pids.uniq.length).to eq(4)
      pids.uniq.each { |pid| expect { Process.waitpid(pid, Process::WNOHANG) }.to raise_error(Errno::ECHILD) }
    end
  end

  it "continues after a parallel worker dies and skips duplicate work" do
    Dir.mktmpdir do |root|
      log = File.join(root, "workers")
      dig = parallel_dig(log)
      failures = []
      dig.define_singleton_method(:write_failure) { |name, **options| failures << [name, options.fetch(:error).message] }
      survey = described_class.new(dig:, output: StringIO.new, jobs: 2)
      expect(survey.run([{name: "killed"}, {name: "safe"}, {name: "safe"}], phase: "require")).to be(false)
      expect(failures).to eq([["killed", "survey worker terminated by signal 9"]])
      expect(File.readlines(log).count { |line| line.start_with?("start") }).to eq(1)
      expect(survey.last_observer_errors).to eq(["safe warning"])
    end
  end

  it "drains worker results larger than pipe capacity" do
    Dir.mktmpdir do |root|
      dig = parallel_dig(File.join(root, "workers"))
      dig.define_singleton_method(:last_observer_errors) { ["x" * 100_000] }
      survey = described_class.new(dig:, output: StringIO.new, jobs: 2)

      expect(survey.run([{name: "one"}, {name: "two"}], phase: "require")).to be(true)
      expect(survey.last_observer_errors.map(&:bytesize)).to eq([100_000, 100_000])
    end
  end

  it "interrupts and reaps every active worker when the parent is interrupted" do
    Dir.mktmpdir do |root|
      log = File.join(root, "workers")
      dig = parallel_dig(log)
      pids = []
      allow(Process).to receive(:fork).and_wrap_original do |original, &block|
        original.call(&block).tap { |pid| pids << pid }
      end
      allow(IO).to receive(:select) do
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
        until File.exist?(log) && File.readlines(log).length >= 2
          raise "workers did not start" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

          sleep 0.01
        end
        raise Interrupt
      end
      expect { described_class.new(dig:, output: StringIO.new, jobs: 2).run([{name: "one"}, {name: "two"}], phase: "require") }.to raise_error(Interrupt)
      expect(pids.length).to eq(2)
      pids.each { |pid| expect { Process.waitpid(pid, Process::WNOHANG) }.to raise_error(Errno::ECHILD) }
    end
  end

  it "accepts top counts above 100 and stops on exhausted stats pages" do
    allow(described_class).to receive(:fetch_page) do |page|
      (1..10).map { |index| %(<a href="/gems/gem#{(page - 1) * 10 + index}">gem</a>) }.join
    end
    expect(described_class.top(101).last).to eq(name: "gem101", version: nil)
    allow(described_class).to receive(:fetch_page).and_return('<a href="/gems/demo">demo</a>')
    expect { described_class.top(3) }.to raise_error(Bonebed::Error, /only 1/)
    expect { described_class.top(0) }.to raise_error(ArgumentError)
  end

  it "parses names and optional versions from a text file" do
    file = Tempfile.new
    file.write("rake 13.4.2\njson # latest\nsinatra - sinatra/base\n\n")
    file.close

    expect(described_class.file(file.path)).to eq([
      {name: "rake", version: "13.4.2"},
      {name: "json", version: nil},
      {name: "sinatra", version: nil, require_path: "sinatra/base"}
    ])
  ensure
    file&.unlink
  end

  it "uses Bundler's parser for lockfile versions" do
    path = File.join(__dir__, "fixtures", "Gemfile.lock")

    expect(described_class.lockfile(path)).to eq([{name: "rake", version: "13.4.2"}])
  end

  it "rejects non-registry sources rather than observing an unrelated registry gem" do
    Tempfile.create("lock") do |file|
      file.write("PATH\n  remote: ../local\n  specs:\n    local-demo (1.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  local-demo!\n")
      file.flush
      expect { described_class.lockfile(file.path) }.to raise_error(ArgumentError, /unsupported.*local-demo/)
    end
  end

  def parallel_dig(log)
    Object.new.tap do |dig|
      dig.define_singleton_method(:prepare_baselines) { |phase:| nil }
      dig.define_singleton_method(:result_exists?) { |*| false }
      dig.define_singleton_method(:run) do |name, **|
        Process.kill("KILL", Process.pid) if name == "killed"
        File.open(log, "a") { |file|
          file.flock(File::LOCK_EX)
          file.puts("start #{Process.pid}")
        }
        sleep 0.15
        File.open(log, "a") { |file|
          file.flock(File::LOCK_EX)
          file.puts("end #{Process.pid}")
        }
        @name = name
      end
      dig.define_singleton_method(:last_errors) { [] }
      dig.define_singleton_method(:last_observer_errors) { ["#{@name} warning"] }
      dig.define_singleton_method(:write_failure) { |*| nil }
    end
  end
end
