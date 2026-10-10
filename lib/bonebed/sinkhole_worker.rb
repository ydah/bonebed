# frozen_string_literal: true

require "bonebed"
require "bonebed/sinkhole"
require "bonebed/sinkhole/server"
require "tempfile"

module Bonebed
  module Sinkhole
    module Worker
      module_function

      def run
        output = IO.for_fd(3)
        output.close_on_exec = true
        output.sync = true
        input = $stdin.read(MAX_INPUT + 1)
        raise ArgumentError, "sinkhole configuration exceeds limit" if input.bytesize > MAX_INPUT
        config = JSON.parse(input, max_nesting: 16)
        $stdin.reopen(File::NULL)
        options = config.fetch("options").transform_keys(&:to_sym)
        Sinkhole.validate_options!(config.fetch("command"), config.fetch("env"), config.fetch("cwd"), config.fetch("timeout"), options)
        raise Unavailable, "network namespace was not isolated" if File.readlink("/proc/self/ns/net") == config.fetch("namespace")
        interfaces = Socket.getifaddrs.map(&:name).uniq.sort
        raise Unavailable, "sinkhole namespace has external interfaces" unless interfaces == ["lo"]
        loopback_up!
        server = Server.new
        drop_capabilities!
        server.start
        Tempfile.create("bonebed-sinkhole-resolver") do |resolver|
          resolver.write("nameserver 127.0.0.1\noptions timeout:1 attempts:1\n")
          resolver.flush
          %i[enforcement resource_limits].each do |key|
            options[key] = options[key].transform_keys(&:to_sym) if options[key]
          end
          Signal.trap("TERM") { raise Timeout::Error, "sinkhole worker terminated" }
          collector = Session.new(config.fetch("command"), env: config.fetch("env"), cwd: config.fetch("cwd"), timeout: config.fetch("timeout"),
            resolver_file: resolver.path, quiet_target: true, **options).run
          server.stop
          collector.network_intent = server.events
          server.errors.each { |message| collector.record_observer_error(:sinkhole, Error.new(message)) }
          state = collector.export_state
          state["isolation"] = "sinkhole_namespace"
          encoded = Sinkhole.encode_response({"collector" => state}, config.fetch("transport_key"))
          raise Unavailable, "sinkhole result exceeds limit" if encoded.bytesize > MAX_OUTPUT
          output.write(encoded)
        end
      rescue => error
        failure = {"error" => "#{error.class}: #{error.message.to_s.byteslice(0, 4096)}"}
        output&.write(Sinkhole.encode_response(failure, config&.fetch("transport_key", "") || ""))
      ensure
        server&.stop
        output&.close
      end

      def loopback_up!
        Socket.open(Socket::AF_INET, Socket::SOCK_DGRAM, 0) do |socket|
          request = "lo".ljust(40, "\0")
          socket.ioctl(0x8913, request)
          request[16, 2] = [request.unpack1("@16s!") | 1].pack("s!")
          socket.ioctl(0x8914, request)
        end
      end

      def drop_capabilities!
        require "seccomp/notify"
        last = Integer(File.read("/proc/sys/kernel/cap_last_cap").strip)
        raise Unavailable, "unsupported capability set" unless (0..128).cover?(last)
        syscall = Fiddle::Function.new(Fiddle::Handle::DEFAULT["syscall"], [Fiddle::TYPE_LONG] * 7, Fiddle::TYPE_LONG)
        invoke = lambda do |name, *arguments|
          result = syscall.call(Seccomp::Notify::Syscalls.number(name), *arguments.fill(0, arguments.length...6))
          raise SystemCallError.new(name.to_s, Fiddle.last_error) if result == -1
          result
        end
        (0..last).each { |capability| invoke.call(:prctl, 24, capability) } # PR_CAPBSET_DROP
        header = Fiddle::Pointer[[0x20080522, 0].pack("L2")]
        capabilities = Fiddle::Pointer["\0" * 24]
        invoke.call(:capset, header.to_i, capabilities.to_i)
        invoke.call(:prctl, 38, 1) # PR_SET_NO_NEW_PRIVS
        invoke.call(:prctl, 4, 0) # PR_SET_DUMPABLE: hide worker memory and result descriptors.
      end
    end
  end
end

Bonebed::Sinkhole::Worker.run if $PROGRAM_NAME == __FILE__
