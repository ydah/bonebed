# frozen_string_literal: true

raise "run only in the disposable fixture harness" unless ENV["BONEBED_ADVERSARIAL_FIXTURE"] == "1"

require "socket"
server = TCPServer.new("127.0.0.1", 0)
server.close
