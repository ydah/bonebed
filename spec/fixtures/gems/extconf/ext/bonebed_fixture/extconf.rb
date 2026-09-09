# frozen_string_literal: true

require "socket"
begin
  TCPSocket.new("127.0.0.1", 9999)
rescue Errno::ECONNREFUSED
  File.write("Makefile", "all:\ninstall:\nclean:\n") unless ENV["BONEBED_FIXTURE_PROBE"]
end
