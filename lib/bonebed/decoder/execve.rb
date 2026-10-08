# frozen_string_literal: true

module Bonebed
  module Decoder
    module Execve
      POINTER_FORMAT = "J"
      POINTER_SIZE = [0].pack(POINTER_FORMAT).bytesize

      module_function

      def call(request, limit: 64)
        raise ArgumentError, "argv limit must be positive" unless limit.is_a?(Integer) && limit.positive?

        argv, truncated = read_argv(request, request.args.fetch(1), limit:)
        event = {
          path: request.read_string(request.args.fetch(0)),
          argv:
        }
        event[:argv_truncated] = true if truncated
        event
      end

      def read_argv(request, address, limit:)
        arguments = []
        (limit + 1).times do |index|
          pointer = request.read(address + (index * POINTER_SIZE), POINTER_SIZE).unpack1(POINTER_FORMAT)
          return [arguments, false] if pointer.zero?
          return [arguments, true] if index == limit

          arguments << request.read_string(pointer)
        end
      end
      private_class_method :read_argv
    end
  end
end
