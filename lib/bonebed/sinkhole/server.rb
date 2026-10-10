# frozen_string_literal: true

require "socket"
require_relative "protocol"

module Bonebed
  module Sinkhole
    class Server
      MAX_CLIENTS = 16
      MAX_EVENTS = 1024
      CLIENT_TIMEOUT = 1.0
      attr_reader :events, :errors

      def initialize(dns_port: 53, http_port: 80, tls_port: 443, ipv6: true)
        @events = []
        @errors = []
        @sockets = {}
        @clients = {}
        @stop_reader, @stop_writer = IO.pipe
        [["127.0.0.1", Socket::AF_INET], *([["::1", Socket::AF_INET6]] if ipv6)].each do |address, family|
          dns = UDPSocket.new(family)
          @sockets[dns] = :dns
          dns.bind(address, dns_port)
          @sockets[TCPServer.new(address, http_port)] = :http
          @sockets[TCPServer.new(address, tls_port)] = :tls
        end
      rescue
        stop
        raise
      end

      def start
        @thread = Thread.new { serve }
        self
      end

      def port(protocol)
        @sockets.find { |_socket, kind| kind == protocol }.first.addr[1]
      end

      def stop
        @stop_writer&.write_nonblock("x", exception: false) unless @stop_writer&.closed?
        @thread&.join(2)
        @thread&.kill if @thread&.alive?
        @thread&.join
        [*@sockets.keys, *@clients.keys, @stop_reader, @stop_writer].compact.each { |socket| socket.close unless socket.closed? }
      end

      private

      def serve
        loop do
          readable = IO.select([@stop_reader, *@sockets.keys, *@clients.keys], nil, nil, 0.1)&.first || []
          break if readable.include?(@stop_reader)
          readable.each { |socket| @sockets.key?(socket) ? accept(socket) : receive(socket) }
          @clients.keys.each { |socket| close(socket) if clock - @clients.fetch(socket)[:started] >= CLIENT_TIMEOUT }
        end
      rescue => error
        @errors << "sinkhole server: #{error.class}: #{error.message}"
      end

      def accept(socket)
        if @sockets.fetch(socket) == :dns
          message, peer = socket.recvfrom_nonblock(4096, exception: false)
          return if message == :wait_readable
          reply = Protocol.dns(message)
          return unless reply
          packet, = reply
          socket.sendmsg_nonblock(packet, 0, Socket.sockaddr_in(peer[1], peer[3]), exception: false)
        else
          client = socket.accept_nonblock(exception: false)
          return if client == :wait_readable
          return client.close if @clients.size >= MAX_CLIENTS
          @clients[client] = {protocol: @sockets.fetch(socket), data: +"".b, started: clock}
        end
      rescue SystemCallError, IOError => error
        @errors << "sinkhole accept: #{error.class}: #{error.message}" if @errors.size < 16
      end

      def receive(socket)
        client = @clients.fetch(socket)
        data = socket.read_nonblock([4096, Protocol::LIMIT - client[:data].bytesize].min, exception: false)
        return if data == :wait_readable
        return close(socket) unless data
        client[:data] << data
        event = Protocol.public_send(client[:protocol], client[:data])
        if event
          record(event)
          response = (client[:protocol] == :http) ? "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" : [21, 0x303, 2, 2, 40].pack("CnnCC")
          socket.write_nonblock(response, exception: false)
          close(socket)
        elsif client[:data].bytesize >= Protocol::LIMIT
          close(socket)
        end
      rescue SystemCallError, IOError
        close(socket)
      end

      def record(event)
        existing = @events.find { |entry| entry.except("count") == event }
        if existing
          existing["count"] += 1
        elsif @events.size < MAX_EVENTS
          @events << event.merge("count" => 1)
        elsif !@errors.include?("sinkhole event limit reached")
          @errors << "sinkhole event limit reached"
        end
      end

      def close(socket)
        @clients.delete(socket)
        socket.close unless socket.closed?
      end

      def clock
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end
  end
end
