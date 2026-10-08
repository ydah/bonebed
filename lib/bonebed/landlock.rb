# frozen_string_literal: true

require "fiddle"
require "rbconfig"

module Bonebed
  module Landlock
    class Unavailable < StandardError; end

    CREATE_RULESET = 444
    ADD_RULE = 445
    RESTRICT_SELF = 446
    PRCTL = {"x86_64" => 157, "aarch64" => 167}.freeze
    READ = (1 << 0) | (1 << 2) | (1 << 3)
    FILE_RIGHTS = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 14) | (1 << 15)
    O_PATH = 0x200000
    O_NOFOLLOW = 0x20000
    O_CLOEXEC = 0x80000

    module_function

    def abi
      raise Unavailable, "Landlock requires x86_64 or aarch64 Linux" unless RUBY_PLATFORM.include?("linux") && PRCTL.key?(RbConfig::CONFIG.fetch("host_cpu"))

      version = call_syscall(CREATE_RULESET, 0, 0, 1)
      raise Unavailable, "Landlock is unavailable" unless version.positive?

      version
    rescue SystemCallError => error
      raise Unavailable, "Landlock is unavailable: #{error.message}"
    end

    # Apply only in the target child immediately before exec; existing sibling threads are unaffected.
    def restrict!(read_paths:, write_paths:, tcp_connect_ports: [], tcp_bind_ports: [])
      reads = paths(read_paths)
      writes = paths(write_paths)
      connects = ports(tcp_connect_ports)
      binds = ports(tcp_bind_ports)
      version = abi
      if version < 4 && (!connects.empty? || !binds.empty?)
        raise Unavailable, "TCP rules require Landlock ABI 4 or newer"
      end
      enforce(reads, writes, connects, binds, version)
      true
    rescue SystemCallError => error
      raise Unavailable, "Landlock enforcement failed: #{error.message}"
    end

    def paths(values)
      raise ArgumentError, "paths must be an array" unless values.is_a?(Array)

      values.map do |path|
        raise ArgumentError, "Landlock paths must be absolute" unless path.is_a?(String) && path.start_with?("/") && !path.include?("\0")

        File.realpath(path)
      rescue SystemCallError => error
        raise ArgumentError, "Landlock path must exist and be accessible: #{path} (#{error.message})"
      end.uniq
    end
    private_class_method :paths

    def ports(values)
      raise ArgumentError, "TCP ports must be integers between 0 and 65535" unless values.is_a?(Array) && values.all? { |port| port.is_a?(Integer) && (0..65_535).cover?(port) }

      values.uniq
    end
    private_class_method :ports

    def enforce(reads, writes, connects, binds, version)
      handled_fs = (1 << 13) - 1
      handled_fs |= 1 << 13 if version >= 2
      handled_fs |= 1 << 14 if version >= 3
      handled_fs |= 1 << 15 if version >= 5
      attributes = (version >= 4) ? [handled_fs, 3].pack("Q2") : [handled_fs].pack("Q")
      ruleset = IO.for_fd(call_syscall(CREATE_RULESET, Fiddle::Pointer[attributes].to_i, attributes.bytesize, 0))
      reads.each { |path| add_path(ruleset.fileno, path, READ) }
      writes.each { |path| add_path(ruleset.fileno, path, handled_fs) }
      {1 => binds, 2 => connects}.each do |access, ports|
        ports.each do |port|
          rule = [access, port].pack("Q2")
          call_syscall(ADD_RULE, ruleset.fileno, 2, Fiddle::Pointer[rule].to_i, 0)
        end
      end
      call_syscall(PRCTL.fetch(RbConfig::CONFIG.fetch("host_cpu")), 38, 1, 0, 0, 0)
      call_syscall(RESTRICT_SELF, ruleset.fileno, 0)
    ensure
      ruleset&.close
    end
    private_class_method :enforce

    def add_path(ruleset, path, access)
      descriptor = IO.for_fd(File.sysopen(path, O_PATH | O_NOFOLLOW | O_CLOEXEC))
      stat = descriptor.stat
      raise ArgumentError, "Landlock path changed to a symbolic link: #{path}" if stat.symlink?

      access &= FILE_RIGHTS unless stat.directory?
      rule = [access, descriptor.fileno].pack("Qi")
      call_syscall(ADD_RULE, ruleset, 1, Fiddle::Pointer[rule].to_i, 0)
    ensure
      descriptor&.close
    end
    private_class_method :add_path

    def call_syscall(number, *arguments)
      function = Fiddle::Function.new(Fiddle::Handle::DEFAULT["syscall"], [Fiddle::TYPE_LONG] * 7, Fiddle::TYPE_LONG, need_gvl: true)
      result = function.call(number, *arguments.fill(0, arguments.length...6))
      raise SystemCallError.new("Landlock syscall #{number}", Fiddle.last_error) if result == -1

      result
    end
    private_class_method :call_syscall
  end
end
