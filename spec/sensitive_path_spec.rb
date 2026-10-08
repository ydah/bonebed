# frozen_string_literal: true

RSpec.describe "sensitive read attempts" do
  it "recognizes home, project, and system credential paths" do
    %w[/h/.aws/credentials /h/.ssh/id_ed25519 /h/.ssh/nested/key /h/.netrc /app/.env /app/config/master.key /etc/shadow].each do |path|
      expect(Bonebed::SensitivePath.match?(path, home: "/h", cwd: "/app")).to be(true), path
    end
    %w[/h/.gemrc /another/.aws/credentials /app/config/ordinary.yml].each do |path|
      expect(Bonebed::SensitivePath.match?(path, home: "/h", cwd: "/app")).to be(false), path
    end
  end

  it "recognizes equivalent absolute paths and roots" do
    %w[/h/./.aws/credentials /h//.ssh/id_ed25519 /app/./config/master.key /etc//shadow].each do |path|
      expect(Bonebed::SensitivePath.match?(path, home: "/h/", cwd: "/app/.")).to be(true), path
    end
    expect(Bonebed::SensitivePath.match?("/.aws/credentials", home: "/", cwd: "/app")).to be(true)
  end

  it "retains sensitive read attempts containing redundant path components" do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")

    Dir.mktmpdir do |home|
      code = 'File.read(ENV.fetch("HOME") + "/./.aws/credentials") rescue nil; File.read(ENV.fetch("HOME") + "//.ssh/id_ed25519") rescue nil'
      observation = Bonebed::Session.new([RbConfig.ruby, "-e", code], env: {"HOME" => home}).run
        .snapshot(Bonebed::PathNormalizer.new(home:))
      expect(observation.dig(:files, :read)).to include("$HOME/./.aws/credentials", "$HOME//.ssh/id_ed25519")
    end
  end

  it "observes credential read attempts in an empty home" do
    skip "Linux seccomp is required" unless RUBY_PLATFORM.include?("linux")

    Dir.mktmpdir do |home|
      code = 'File.read(File.expand_path("~/.aws/credentials")) rescue nil'
      observation = Bonebed::Session.new([RbConfig.ruby, "-e", code], env: {"HOME" => home}).run
        .snapshot(Bonebed::PathNormalizer.new(home:))
      expect(observation.dig(:files, :read)).to have_key("$HOME/.aws/credentials")
    end
  end
end
