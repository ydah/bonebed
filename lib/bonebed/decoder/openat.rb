# frozen_string_literal: true

module Bonebed
  module Decoder
    module Openat
      module_function

      def call(request, syscall: request.syscall)
        path_argument, flags_argument = syscall == :open ? [0, 1] : [1, 2]
        {
          path: request.read_string(request.args.fetch(path_argument)),
          mode: (request.args.fetch(flags_argument) & (File::WRONLY | File::RDWR)).zero? ? :read : :write
        }
      end
    end
  end
end
