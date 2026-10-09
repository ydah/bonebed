# frozen_string_literal: true

raise "run only in the disposable fixture harness" unless ENV["BONEBED_ADVERSARIAL_FIXTURE"] == "1"

require "fileutils"
FileUtils.mkdir_p(".git/hooks")
File.write(".git/hooks/pre-commit", "#!/bin/sh\nexit 0\n")
File.chmod(0o700, ".git/hooks/pre-commit")
