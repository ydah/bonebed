# frozen_string_literal: true

require "fileutils"
require "json"
require "rbconfig"
require "tmpdir"
require "bonebed/cli"

RSpec.describe "fixture manifests" do
  it "matches all six known syscall profiles" do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")

    Dir.mktmpdir("bonebed-fixtures-") do |root|
      home = File.join(root, "home")
      tmpdir = File.join(root, "tmp")
      FileUtils.mkdir_p([home, tmpdir])
      File.write(File.join(home, ".bonebed_test"), "fixture")
      env = {"HOME" => home, "TMPDIR" => tmpdir}
      normalizer = Bonebed::PathNormalizer.new(home:, tmpdir:)
      baseline = observe([RbConfig.ruby, "-e", ""], env, normalizer)

      %w[quiet reader writer net exec extconf].each do |fixture|
        actual = capabilities(Bonebed::Difference.call(observe(command(fixture), env.merge(probe_env(fixture)), normalizer), baseline))
        expected = JSON.parse(File.read(File.join(__dir__, "fixtures", "golden", "#{fixture}.json")))
        expect(actual).to eq(expected), "#{fixture} manifest differed"
      end
    end
  end

  it "accepts a distinct require path and reports target failures" do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")

    Dir.mktmpdir("bonebed-require-path-") do |results|
      expect(Bonebed::CLI.start(["dig", "seccomp-notify", "--require", "missing", "--results", results])).to eq(1)
      failed = JSON.parse(File.read(Dir[File.join(results, "**", "*.json")].first))
      expect(failed.fetch("stderr")).to include("cannot load such file -- missing")

      expect(Bonebed::CLI.start(["dig", "seccomp-notify", "--results", results])).to eq(0)

      manifest = Dir[File.join(results, "**", "*.json")].map { |path| JSON.parse(File.read(path)) }.find { |entry| entry.dig("gem", "require_path") == "seccomp/notify" }
      expect(manifest.dig("gem", "require_path")).to eq("seccomp/notify")
      expect(manifest.fetch("errors")).to be_empty
    end
  end

  it "captures target stdout and stderr" do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")

    collector = nil
    expect do
      collector = Bonebed::Session.new([RbConfig.ruby, "-e", 'puts "captured stdout"; warn "captured stderr"']).run
    end.to output("captured stdout\n").to_stdout.and output("captured stderr\n").to_stderr
    observation = collector.snapshot(Bonebed::PathNormalizer.new)

    expect(observation.values_at(:stdout, :stderr)).to eq(["captured stdout\n", "captured stderr\n"])
  end

  it "resolves relative writes and drops nonexistent read probes" do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")

    Dir.mktmpdir("bonebed-relative-") do |root|
      code = 'File.read("missing") rescue nil; File.write("created", "ok")'
      observation = Bonebed::Session.new([RbConfig.ruby, "-e", code], cwd: root).run.snapshot(
        Bonebed::PathNormalizer.new(cwd: root)
      )

      expect(observation.dig(:files, :read)).not_to have_key("$PWD/missing")
      expect(observation.dig(:files, :write)).to have_key("$PWD/created")
    end
  end

  it "observes Ruby thread creation" do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")

    observation = Bonebed::Session.new([RbConfig.ruby, "-e", "Thread.new {}.join"]).run.snapshot(
      Bonebed::PathNormalizer.new
    )

    expect(observation.fetch(:threads).keys).to include(include(syscall: satisfy { |value| %w[clone clone3].include?(value) }))
  end

  it "ends a stream cleanly when another thread closes it" do
    reader = instance_double(IO, readpartial: nil, closed?: true)
    allow(reader).to receive(:readpartial).and_raise(IOError, "stream closed in another thread")

    thread = Bonebed::Session.new([RbConfig.ruby, "-e", ""]).send(:stream, reader, StringIO.new)

    expect { thread.value }.not_to raise_error
  end

  it "releases file descriptors and worker threads between sessions" do
    skip "Linux procfs and seccomp are required" unless RUBY_PLATFORM.include?("linux")

    descriptors = Dir["/proc/self/fd/*"].size
    threads = Thread.list.size
    3.times { Bonebed::Session.new([RbConfig.ruby, "-e", ""]).run }

    expect(Dir["/proc/self/fd/*"].size).to be <= descriptors
    expect(Thread.list.size).to eq(threads)
  end

  it "kills target descendants and closes streams on timeout" do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")

    Dir.mktmpdir("bonebed-timeout-") do |root|
      marker = File.join(root, "orphan")
      code = <<~RUBY
        spawn(ARGV.fetch(0), "--disable-gems", "-e", "sleep 2; File.write(ARGV.fetch(0), 'orphan')", ARGV.fetch(1))
        puts "started"
        STDOUT.flush
        sleep 5
      RUBY
      collector = Bonebed::Session.new([RbConfig.ruby, "--disable-gems", "-e", code, RbConfig.ruby, marker], timeout: 1).run
      sleep 2.1
      observation = collector.snapshot(Bonebed::PathNormalizer.new)

      expect(observation.fetch(:stdout)).to include("started")
      expect(observation.fetch(:errors)).to include(match(/timed out/))
      expect(File.exist?(marker)).to be(false)
    end
  end

  def command(fixture)
    root = File.join(__dir__, "fixtures", "gems", fixture)
    return [RbConfig.ruby, File.join(root, "ext", "bonebed_fixture", "extconf.rb")] if fixture == "extconf"

    [RbConfig.ruby, "-I#{File.join(root, "lib")}", "-e", "require ARGV.fetch(0)", "bonebed-fixture-#{fixture}"]
  end

  def probe_env(fixture)
    (fixture == "extconf") ? {"BONEBED_FIXTURE_PROBE" => "1"} : {}
  end

  def observe(command, env, normalizer)
    Bonebed::Session.new(command, env:).run.snapshot(normalizer)
  end

  def capabilities(observation)
    reads = observation.dig(:files, :read).keys.grep(/\A\$HOME\//).sort
    writes = observation.dig(:files, :write).keys.grep(/\A(?:\$HOME|\$TMPDIR)\//).sort
    {
      "files" => {"read" => reads, "write" => writes, "notable" => (reads + writes).uniq.sort},
      "network" => observation[:network].keys.map { |event| event.transform_keys(&:to_s) }.sort_by(&:to_s),
      "exec" => observation[:exec].keys.map { |event| event.slice(:path, :argv).transform_keys(&:to_s) }.sort_by(&:to_s)
    }
  end
end
