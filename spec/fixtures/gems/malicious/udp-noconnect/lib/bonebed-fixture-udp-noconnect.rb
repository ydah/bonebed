# frozen_string_literal: true

raise "run only in the disposable fixture harness" unless ENV["BONEBED_ADVERSARIAL_FIXTURE"] == "1"

require "socket"
begin
  payload = "fixture"
  UDPSocket.new.send(payload, 0, "127.0.0.1", Integer(ENV.fetch("BONEBED_FIXTURE_PORT")))
rescue Errno::ENETUNREACH
  puts "udp blocked"
end
