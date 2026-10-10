# frozen_string_literal: true

require "fiddle"
require "rbconfig"
require "socket"
require "open3"

module Bonebed
  module Isolation
    class Unavailable < StandardError; end

    SYSCALLS = {
      "x86_64" => {unshare: 272, prctl: 157, landlock_create_ruleset: 444, pidfd_open: 434, pidfd_send_signal: 424},
      "aarch64" => {unshare: 97, prctl: 167, landlock_create_ruleset: 444, pidfd_open: 434, pidfd_send_signal: 424}
    }.freeze
    CLONE_NEWUSER = 0x10000000
    CLONE_NEWNET = 0x40000000
    PR_SET_CHILD_SUBREAPER = 36

    module_function

    def features
      abi = nil
      landlock_error = nil
      begin
        abi = syscall!(:landlock_create_ruleset, 0, 0, 1)
      rescue Unavailable, SystemCallError => error
        landlock_error = error.message
      end
      namespace_error = nil
      begin
        offline_command(["/bin/true"])
      rescue Unavailable => error
        namespace_error = error.message
      end
      {
        landlock_abi: abi, landlock_error:,
        max_user_namespaces: setting("/proc/sys/user/max_user_namespaces"),
        apparmor_userns_restricted: setting("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
        network_namespace: namespace_error.nil?, network_namespace_error: namespace_error,
        in_process_network_namespace_error: probe_offline,
        cgroup_v2: File.exist?("/sys/fs/cgroup/cgroup.controllers"),
        cgroup_writable: File.writable?("/sys/fs/cgroup")
      }
    end

    # The new namespace has no external interfaces; loopback stays down in strict offline mode.
    def offline_command(command)
      raise ArgumentError, "command must be a nonempty array of strings" unless command.is_a?(Array) && !command.empty? && command.all? { |argument| argument.is_a?(String) && !argument.include?("\0") }
      raise Unavailable, "network namespaces require Linux" unless RUBY_PLATFORM.include?("linux")

      executable = %w[/usr/bin/unshare /bin/unshare].find { |path| File.executable?(path) }
      raise Unavailable, "util-linux unshare is not installed" unless executable

      prefix = [executable, "--user", "--map-root-user", "--net", "--"]
      _, stderr, status = Open3.capture3(*prefix, "/bin/true")
      raise Unavailable, "network namespace unavailable: #{stderr.strip}" unless status.success?

      [*prefix, *command]
    rescue SystemCallError => error
      raise Unavailable, "network namespace unavailable: #{error.message}"
    end

    # Call only in the disposable target child: namespace changes cannot be undone here.
    def offline!
      uid, gid = Process.uid, Process.gid
      syscall!(:unshare, CLONE_NEWUSER | CLONE_NEWNET)
      File.write("/proc/self/uid_map", "0 #{uid} 1\n")
      File.write("/proc/self/setgroups", "deny\n") if File.exist?("/proc/self/setgroups")
      File.write("/proc/self/gid_map", "0 #{gid} 1\n")
      Socket.open(Socket::AF_INET, Socket::SOCK_DGRAM, 0) do |socket|
        request = "lo".ljust(40, "\0")
        socket.ioctl(0x8913, request) # SIOCGIFFLAGS: preserve existing interface flags.
        request[16, 2] = [request.unpack1("@16s!") | 1].pack("s!")
        socket.ioctl(0x8914, request)
      end
      true
    rescue SystemCallError => error
      raise Unavailable, "network namespace unavailable: #{error.message}"
    end

    def subreaper!
      syscall!(:prctl, PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
      true
    rescue SystemCallError => error
      raise Unavailable, "child subreaper unavailable: #{error.message}"
    end

    def target_dumpable!
      syscall!(:prctl, 4, 1, 0, 0, 0)
    end

    def descendants(root_pid)
      processes = Dir["/proc/[0-9]*/stat"].filter_map do |path|
        pid = File.basename(File.dirname(path)).to_i
        info = process_info(pid)
        [pid, info] if info
      end.to_h
      found = {}
      loop do
        previous = found.size
        processes.each do |pid, info|
          next if pid == root_pid || found.key?(pid)
          found[pid] = info[:started_at] if info[:parent] == root_pid || found.key?(info[:parent])
        end
        break if found.size == previous
      end
      found
    end

    # ponytail: only tracked descendants are recoverable; use a delegated cgroup for race-free whole-tree cleanup.
    def cleanup(tracked)
      tracked.reverse_each.filter_map do |pid, started_at|
        next if pid == Process.pid || process_info(pid)&.fetch(:started_at) != started_at

        descriptor = nil
        begin
          descriptor = IO.for_fd(syscall!(:pidfd_open, pid, 0))
          next if process_info(pid)&.fetch(:started_at) != started_at

          syscall!(:pidfd_send_signal, descriptor.fileno, Signal.list.fetch("KILL"), 0, 0)
          exited = IO.select([descriptor], nil, nil, 1)
          begin
            Process.waitpid(pid, Process::WNOHANG)
          rescue Errno::ECHILD
            nil
          end
          "descendant #{pid} did not exit after SIGKILL" unless exited
        rescue Errno::ESRCH
          nil
        rescue Unavailable, SystemCallError => error
          "descendant #{pid}: #{error.message}"
        ensure
          descriptor&.close
        end
      end
    end

    def process_info(pid)
      return unless pid.is_a?(Integer) && pid.positive?

      stat = File.read("/proc/#{pid}/stat")
      fields = stat[(stat.rindex(")") || stat.length) + 2..]&.split
      return unless fields && fields.length >= 20

      {parent: Integer(fields[1]), started_at: Integer(fields[19])}
    rescue SystemCallError, ArgumentError
      nil
    end

    def syscall!(name, *arguments)
      raise Unavailable, "Linux isolation requires x86_64 or aarch64 Linux" unless RUBY_PLATFORM.include?("linux")

      numbers = SYSCALLS[RbConfig::CONFIG.fetch("host_cpu")]
      raise Unavailable, "unsupported isolation architecture" unless numbers

      function = Fiddle::Function.new(Fiddle::Handle::DEFAULT["syscall"], [Fiddle::TYPE_LONG] * 7, Fiddle::TYPE_LONG, need_gvl: true)
      result = function.call(numbers.fetch(name), *arguments.fill(0, arguments.length...6))
      raise SystemCallError.new(name.to_s, Fiddle.last_error) if result == -1

      result
    end
    private_class_method :syscall!

    def setting(path)
      Integer(File.read(path).strip)
    rescue SystemCallError, ArgumentError
      nil
    end
    private_class_method :setting

    def probe_offline
      return "Linux namespaces are unavailable" unless RUBY_PLATFORM.include?("linux")

      reader, writer = IO.pipe
      pid = Process.fork do
        reader.close
        begin
          offline!
        rescue Unavailable => error
          writer.write(error.message)
        ensure
          writer.close
        end
        exit! 0
      end
      writer.close
      unless IO.select([reader], nil, nil, 2)
        Process.kill("KILL", pid)
        return "network namespace probe timed out"
      end
      error = reader.read
      _, status = Process.waitpid2(pid)
      return "network namespace probe failed (#{status})" unless status.success?

      error.empty? ? nil : error
    rescue SystemCallError => error
      error.message
    ensure
      reader&.close
      writer&.close unless writer&.closed?
      begin
        Process.waitpid(pid) if pid
      rescue Errno::ECHILD
        nil
      end
    end
    private_class_method :probe_offline
  end
end
