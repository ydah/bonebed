# frozen_string_literal: true

module Bonebed
  module Decoder
    module Openat
      AT_FDCWD = -100

      module_function

      def call(request, syscall: request.syscall, cwd: nil)
        path_argument, flags_argument = (syscall == :open) ? [0, 1] : [1, 2]
        path = request.read_string(request.args.fetch(path_argument))
        {
          path: resolve(path, request, syscall, cwd),
          mode: write?(request.args.fetch(flags_argument)) ? :write : :read
        }
      end

      def resolve(path, request, syscall, cwd, dirfd: nil)
        return path if path.start_with?(File::SEPARATOR)

        dirfd = signed(dirfd || request.args.fetch(0)) unless syscall == :open
        link = (dirfd.nil? || dirfd == AT_FDCWD) ? "cwd" : "fd/#{dirfd}"
        File.expand_path(path, File.readlink("/proc/#{request.pid}/#{link}"))
      rescue SystemCallError
        (link == "cwd" && cwd) ? File.expand_path(path, cwd) : path
      end

      def signed(value)
        value &= (1 << 32) - 1
        (value >= (1 << 31)) ? value - (1 << 32) : value
      end
      private_class_method :signed

      def write?(flags)
        write_flags = File::WRONLY | File::RDWR | File::CREAT | File::TRUNC | File::APPEND
        !(flags & write_flags).zero?
      end
      private_class_method :write?
    end
  end
end
