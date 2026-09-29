# frozen_string_literal: true

module Bonebed
  module Decoder
    module Clone
      CLONE_THREAD = 0x00010000
      module_function

      def call(request, syscall: request.syscall)
        flags = if syscall == :clone3
          return if request.args.fetch(1) < 8

          request.read(request.args.fetch(0), 8).unpack1("Q<")
        else
          request.args.fetch(0)
        end
        {syscall: syscall.to_s} unless (flags & CLONE_THREAD).zero?
      end
    end
  end
end
