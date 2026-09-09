# frozen_string_literal: true

require "fileutils"
require "json"
require "rbconfig"
require "tmpdir"

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

  def command(fixture)
    root = File.join(__dir__, "fixtures", "gems", fixture)
    return [RbConfig.ruby, File.join(root, "ext", "bonebed_fixture", "extconf.rb")] if fixture == "extconf"

    [RbConfig.ruby, "-I#{File.join(root, "lib")}", "-e", "require ARGV.fetch(0)", "bonebed-fixture-#{fixture}"]
  end

  def probe_env(fixture)
    fixture == "extconf" ? {"BONEBED_FIXTURE_PROBE" => "1"} : {}
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
      "exec" => observation[:exec].keys.map { |event| event.transform_keys(&:to_s) }.sort_by(&:to_s)
    }
  end
end
