# frozen_string_literal: true

raise "run only in the disposable fixture harness" unless ENV["BONEBED_ADVERSARIAL_FIXTURE"] == "1"

if ENV["CI"] == "true"
  require "socket"
  payload = "fixture"
  UDPSocket.new.send(payload, 0, "127.0.0.1", 9)
end
