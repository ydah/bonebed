# frozen_string_literal: true

raise "run only in the disposable fixture harness" unless ENV["BONEBED_ADVERSARIAL_FIXTURE"] == "1"

require "socket"
socket = Socket.new(Socket::AF_NETLINK, Socket::SOCK_RAW, 0)
socket.connect([Socket::AF_NETLINK, 0, 0, 0].pack("SSII"))
socket.close
