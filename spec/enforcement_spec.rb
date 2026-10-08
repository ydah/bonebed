# frozen_string_literal: true

require "bonebed/enforcement"

RSpec.describe Bonebed::Enforcement do
  it "combines network namespaces with enforced paths and denies an ungranted file" do
    skip "Linux Landlock is required" unless RUBY_PLATFORM.include?("linux") && Bonebed::Landlock.abi.positive?
    Bonebed::Isolation.offline_command([RbConfig.ruby, "-e", ""])
    Dir.mktmpdir do |outside|
      denied = File.join(outside, "secret")
      File.write(denied, "not allowed")
      Bonebed::GemEnvironment.open do |environment|
        policy_file = File.join(environment.root, "policy.yml")
        File.write(policy_file, "{}\n")
        code = 'File.write("allowed", "ok"); begin; File.read(ARGV.fetch(0)); abort "escaped"; rescue Errno::EACCES; puts "denied"; end'
        result = Bonebed::Session.new([RbConfig.ruby, "-e", code, denied], env: environment.env,
          cwd: environment.project, unsetenv_others: true, offline: true, quiet_target: true,
          enforcement: described_class.load(policy_file, environment)).run.snapshot(environment.normalizer)
        expect(result[:errors]).to be_empty
        expect(result[:observer_errors]).to be_empty
        expect(result[:stdout]).to eq("denied\n")
        expect(result[:isolation]).to eq("network_namespace")
        expect(File.read(File.join(environment.project, "allowed"))).to eq("ok")
      end
    end
  rescue Bonebed::Isolation::Unavailable => error
    skip error.message
  end

  it "resolves explicit target paths and rejects unrecognized policy fields" do
    Bonebed::GemEnvironment.open do |environment|
      path = File.join(environment.root, "policy.yml")
      File.write(path, "read_paths: ['$HOME/.aws']\ntcp_connect_ports: [443]\n")
      policy = described_class.load(path, environment)
      expect(policy[:read_paths]).to include(File.join(environment.home, ".aws"))
      expect(policy[:write_paths]).to include(environment.root)
      expect(policy[:tcp_connect_ports]).to eq([443])
      File.write(path, "allow_everything: true\n")
      expect { described_class.load(path, environment) }.to raise_error(ArgumentError)
    end
  end
end
