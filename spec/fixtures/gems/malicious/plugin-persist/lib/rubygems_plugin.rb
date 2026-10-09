# frozen_string_literal: true

raise "run only in the disposable fixture harness" unless ENV["BONEBED_ADVERSARIAL_FIXTURE"] == "1"

File.open(File.join(Dir.home, ".bashrc"), "a") { |file| file.puts("# inert Bonebed fixture marker") }
