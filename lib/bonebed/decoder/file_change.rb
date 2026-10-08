# frozen_string_literal: true

require_relative "openat"

module Bonebed
  module Decoder
    module FileChange
      module_function

      def call(request, syscall:, cwd: nil)
        args = request.args
        case syscall
        when :unlink, :rmdir
          {operation: :delete, path: path(request, 0, cwd:)}
        when :unlinkat
          {operation: :delete, path: path(request, 1, dirfd: args.fetch(0), cwd:)}
        when :rename, :link
          {operation: (syscall == :rename) ? :rename : :link, from: path(request, 0, cwd:), to: path(request, 1, cwd:)}
        when :renameat, :renameat2, :linkat
          {operation: (syscall == :linkat) ? :link : :rename,
           from: path(request, 1, dirfd: args.fetch(0), cwd:), to: path(request, 3, dirfd: args.fetch(2), cwd:)}
        when :symlink, :symlinkat
          to = (syscall == :symlink) ? path(request, 1, cwd:) : path(request, 2, dirfd: args.fetch(1), cwd:)
          {operation: :link, from: request.read_string(args.fetch(0)), to:, symbolic: true}
        when :mkdir, :chmod, :creat
          operation = (syscall == :creat) ? :write : syscall
          {operation:, path: path(request, 0, cwd:), mode: args.fetch(1)}
        when :mkdirat, :fchmodat, :fchmodat2
          operation = (syscall == :mkdirat) ? :mkdir : :chmod
          {operation:, path: path(request, 1, dirfd: args.fetch(0), cwd:), mode: args.fetch(2)}
        when :chown, :lchown
          {operation: :chown, path: path(request, 0, cwd:), uid: args.fetch(1), gid: args.fetch(2)}
        when :fchownat
          {operation: :chown, path: path(request, 1, dirfd: args.fetch(0), cwd:), uid: args.fetch(2), gid: args.fetch(3)}
        when :fchmod
          {operation: :chmod, path: File.readlink("/proc/#{request.pid}/fd/#{args.fetch(0)}"), mode: args.fetch(1)}
        when :fchown
          {operation: :chown, path: File.readlink("/proc/#{request.pid}/fd/#{args.fetch(0)}"), uid: args.fetch(1), gid: args.fetch(2)}
        when :truncate, :ftruncate
          target = (syscall == :truncate) ? path(request, 0, cwd:) : File.readlink("/proc/#{request.pid}/fd/#{args.fetch(0)}")
          {operation: :truncate, path: target, length: args.fetch(1)}
        else
          raise ArgumentError, "unsupported file change syscall: #{syscall}"
        end
      end

      def path(request, index, cwd:, dirfd: nil)
        value = request.read_string(request.args.fetch(index))
        Openat.resolve(value, request, dirfd.nil? ? :open : :openat, cwd, dirfd:)
      end
      private_class_method :path
    end
  end
end
