# frozen_string_literal: true

raise "run only in the disposable fixture harness" unless ENV["BONEBED_ADVERSARIAL_FIXTURE"] == "1"

require "socket"
payload = "fixture"
at_exit { UDPSocket.new.send(payload, 0, "127.0.0.1", 9) }
