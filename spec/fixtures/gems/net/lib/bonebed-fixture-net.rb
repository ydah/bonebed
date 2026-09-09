# frozen_string_literal: true

require "socket"
begin
  TCPSocket.new("127.0.0.1", 9999)
rescue Errno::ECONNREFUSED
  nil
end
