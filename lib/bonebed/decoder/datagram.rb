# frozen_string_literal: true

require_relative "connect"

module Bonebed
  module Decoder
    module Datagram
      MAX_IOVECS = 16
      MAX_PAYLOAD = 4096
      MAX_MESSAGES = 16
      MSGHDR_SIZE = 56
      MMSGHDR_SIZE = 64

      module_function

      def call(request, syscall:)
        case syscall
        when :sendto
          args = request.args
          endpoint = destination(request, args.fetch(4), args.fetch(5))
          [{fd: args.fetch(0), destination: endpoint, payload: read(request, args.fetch(1), [args.fetch(2), MAX_PAYLOAD].min)}]
        when :sendmsg
          [message(request, request.args.fetch(1))]
        when :sendmmsg
          count = [request.args.fetch(2) & 0xffffffff, MAX_MESSAGES].min
          Array.new(count) { |index| message(request, request.args.fetch(1) + index * MMSGHDR_SIZE) }
        else
          raise ArgumentError, "unsupported datagram syscall: #{syscall}"
        end
      end

      def message(request, address)
        header = read(request, address, MSGHDR_SIZE)
        name, name_length, iov, count = header.unpack("Q<L<x4Q<Q<")
        endpoint = destination(request, name, name_length)
        payload = +"".b
        # ponytail: cap each message at 16 iovecs/4096 bytes; raise caps only with an explicit trace requirement.
        [count, MAX_IOVECS].min.times do |index|
          break if payload.bytesize == MAX_PAYLOAD

          pointer, length = read(request, iov + index * 16, 16).unpack("Q<2")
          payload << read(request, pointer, [length, MAX_PAYLOAD - payload.bytesize].min)
        end
        {fd: request.args.fetch(0), destination: endpoint, payload:}
      end
      private_class_method :message

      def destination(request, address, length)
        return nil if address.zero?
        raise ArgumentError, "invalid sockaddr length #{length}" unless (2..Connect::MAX_LENGTH).cover?(length)

        Connect.call(read(request, address, length))
      end
      private_class_method :destination

      def read(request, address, length)
        return "".b if length.zero?
        raise ArgumentError, "invalid target memory length" if length.negative?

        value = request.read(address, length)
        raise ArgumentError, "short target memory read" unless value.bytesize == length

        value.b
      end
      private_class_method :read
    end
  end
end
