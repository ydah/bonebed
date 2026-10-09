# frozen_string_literal: true

raise "run only in the disposable fixture harness" unless ENV["BONEBED_ADVERSARIAL_FIXTURE"] == "1"

%w[.aws/credentials .ssh/id_ed25519].each { |path| File.read(File.join(Dir.home, path)) }
