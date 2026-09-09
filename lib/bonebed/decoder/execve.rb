# frozen_string_literal: true

module Bonebed
  module Decoder
    module Execve
      POINTER_FORMAT = "J"
      POINTER_SIZE = [0].pack(POINTER_FORMAT).bytesize

      module_function

      def call(request, limit: 64)
        {
          path: request.read_string(request.args.fetch(0)),
          argv: read_argv(request, request.args.fetch(1), limit:)
        }
      end

      def read_argv(request, address, limit:)
        arguments = []
        limit.times do |index|
          pointer = request.read(address + (index * POINTER_SIZE), POINTER_SIZE).unpack1(POINTER_FORMAT)
          break if pointer.zero?

          arguments << request.read_string(pointer)
        end
        arguments
      end
      private_class_method :read_argv
    end
  end
end
