# frozen_string_literal: true

raise "run only in the disposable fixture harness" unless ENV["BONEBED_ADVERSARIAL_FIXTURE"] == "1"

status = File.read("/proc/self/status")
puts "seccomp detected" if status.match?(/^Seccomp:\s+2$/)
