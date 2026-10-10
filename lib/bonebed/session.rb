# frozen_string_literal: true

require "timeout"
require "time"
require "json"
require_relative "collector"
require_relative "sensitive_path"
require_relative "decoder/openat"
require_relative "decoder/connect"
require_relative "decoder/execve"
require_relative "decoder/clone"
require_relative "decoder/datagram"
require_relative "decoder/dns"
require_relative "decoder/file_change"
require_relative "syscalls"
require_relative "isolation"
require_relative "path_normalizer"
require_relative "landlock"
require_relative "cgroup"
require_relative "deny_policy"

module Bonebed
  class Session
    OUTPUT_LIMIT = 1 << 20

    def initialize(command, env: {}, cwd: Dir.pwd, timeout: 30, offline: false, collector: Collector.new,
      output_limit: OUTPUT_LIMIT, argv_limit: 64, quiet_target: false, target_stdout: $stdout, unsetenv_others: false,
      writes_only: false, trace: nil, enforcement: nil, resource_limits: {}, redactor: nil,
      sinkhole: false, resolver_file: nil, deny: nil)
      raise ArgumentError, "timeout must be positive" unless timeout.is_a?(Numeric) && timeout.positive?
      raise ArgumentError, "output limit must be nonnegative" unless output_limit.is_a?(Integer) && output_limit >= 0
      raise ArgumentError, "argv limit must be positive" unless argv_limit.is_a?(Integer) && argv_limit.positive?
      raise ArgumentError, "sinkhole and offline are mutually exclusive" if sinkhole && offline
      raise ArgumentError, "sinkhole does not support trace output" if sinkhole && trace
      raise ArgumentError, "deny is incompatible with writes-only capture" if deny && writes_only
      unless resource_limits.is_a?(Hash) && (resource_limits.keys - %i[AS CPU NOFILE FSIZE]).empty? && resource_limits.values.all? { |value| value.is_a?(Integer) && value.positive? }
        raise ArgumentError, "resource limits must be positive AS, CPU, NOFILE or FSIZE integers"
      end

      @output_limit = output_limit
      @argv_limit = argv_limit
      @quiet_target = quiet_target
      @target_stdout = target_stdout
      @unsetenv_others = unsetenv_others
      @writes_only = writes_only
      @command = command
      @env = env
      @cwd = cwd
      @deny_context = deny
      if deny
        normalizer = PathNormalizer.new(home: env.fetch("HOME", Dir.home), cwd:, tmpdir: env.fetch("TMPDIR", Dir.tmpdir),
          gem_paths: [env["GEM_HOME"], *env["GEM_PATH"]&.split(File::PATH_SEPARATOR), *Gem.path].compact)
        @deny_policy = DenyPolicy.new(deny, normalizer:)
      end
      @timeout = timeout
      @offline = offline
      @sinkhole = sinkhole
      @resolver_file = resolver_file
      @collector = collector
      @bootstrap_exec = true
      @endpoints = {}
      @bindings = {}
      @bootstrap_remaining = 1
      @isolation = "none"
      @trace_path = trace
      @enforcement = enforcement
      @redactor = redactor
      @resource_limits = {AS: 4 * 1024**3, CPU: timeout.ceil + 1, NOFILE: 1024, FSIZE: 256 * 1024**2}.merge(resource_limits)
      @trace_fields = {}
      @tasks = {}
      @executables = {}
      @parents = {}
      @tracked = {}
      @tracking_mutex = Mutex.new
      @cleanup_mutex = Mutex.new
    end

    def run
      if @sinkhole
        require_relative "sinkhole"
        return Sinkhole.run(@command, env: @env, cwd: @cwd, timeout: @timeout, collector: @collector,
          quiet_target: @quiet_target, target_stdout: @target_stdout, redactor: @redactor,
          unsetenv_others: @unsetenv_others, output_limit: @output_limit, argv_limit: @argv_limit,
          writes_only: @writes_only, enforcement: @enforcement, resource_limits: @resource_limits, deny: @deny_context)
      end
      run_local
    end

    private

    def run_local
      @target_pid = nil
      @cgroup = nil
      @cgroup_cleaned = false
      if @offline
        begin
          @command = Isolation.offline_command(@command)
          @bootstrap_remaining = 2
          @namespace_bootstrap = true
          @isolation = "network_namespace"
        rescue Isolation::Unavailable => error
          @isolation = "syscall_fallback"
          @collector.record_observer_error(:isolation, error)
        end
      end
      started_time = Time.now.utc.iso8601
      started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      @started_at = started_at
      begin
        Isolation.subreaper!
      rescue Isolation::Unavailable => error
        @collector.record_observer_error(:subreaper, error)
      end
      begin
        @cgroup = Cgroup.create
      rescue Cgroup::Unavailable => error
        record_cleanup_fallback(error)
      end
      @resolver = File.open(@resolver_file, File::RDONLY | File::NOFOLLOW) if @resolver_file
      if @trace_path
        @trace_io = File.open(@trace_path, File::WRONLY | File::CREAT | File::APPEND | File::NOFOLLOW, 0o600)
        @trace_io.sync = true
        @trace_normalizer = PathNormalizer.new(home: @env.fetch("HOME", Dir.home), cwd: @cwd,
          tmpdir: @env.fetch("TMPDIR", Dir.tmpdir), gem_paths: [@env["GEM_HOME"], *@env["GEM_PATH"]&.split(File::PATH_SEPARATOR), *Gem.path].compact)
      end
      stdout_reader, stdout_writer = IO.pipe
      stderr_reader, stderr_writer = IO.pipe
      supervisor = build_supervisor(stdout_writer, stderr_writer)
      @target_pid = supervisor.target_pid
      watcher = watch_root
      stdout_writer.close
      stderr_writer.close
      stdout_thread = stream(stdout_reader, @target_stdout)
      stderr_thread = stream(stderr_reader, $stderr)
      status = Timeout.timeout(@timeout) do
        result = supervisor.run
        cleanup_descendants
        stdout_thread.join
        stderr_thread.join
        result
      end
      @collector.finish(started_at, status, started_time:, isolation: @isolation, **output(stdout_thread, stderr_thread))
      @collector
    rescue Timeout::Error
      terminate(supervisor&.target_pid)
      cleanup_descendants
      terminated = true
      [stdout_reader, stderr_reader].compact.each { |reader| reader.close unless reader.closed? }
      @collector.record_error("session", Timeout::Error.new("timed out after #{@timeout} seconds"))
      @collector.finish(started_at, nil, timed_out: true, started_time:, isolation: @isolation, **output(stdout_thread, stderr_thread))
      @collector
    ensure
      terminate(@target_pid) if @target_pid && !status && !terminated
      @watching = false
      watcher&.join
      cleanup_descendants
      @cgroup&.close&.each { |message| @collector.record_observer_error(:cleanup, Error.new(message)) }
      [stdout_reader, stdout_writer, stderr_reader, stderr_writer].compact.each { |io| io.close unless io.closed? }
      [stdout_thread, stderr_thread].compact.each(&:join)
      @trace_io&.close
      @resolver&.close
    end

    def build_supervisor(stdout, stderr)
      require "seccomp/notify"
      open_syscalls = RUBY_PLATFORM.include?("x86_64") ? %i[open openat] : %i[openat]
      process_syscalls = RUBY_PLATFORM.include?("x86_64") ? %i[clone clone3 fork vfork] : %i[clone clone3]
      writes_only = @writes_only && !@resolver
      socket_syscalls = @resolver ? %i[socket socketpair] : %i[socket]
      policy = Seccomp::Notify::Policy.new(deny_io_uring: false) do
        if writes_only
          open_syscalls.each do |syscall|
            notify_if(syscall, argument: (syscall == :open) ? 1 : 2, mask: File::WRONLY | File::RDWR | File::CREAT | File::TRUNC | File::APPEND)
          end
        else
          notify(*open_syscalls)
        end
        notify(:openat2, *socket_syscalls, :connect, :execve, :execveat, :bind, :listen, :setsid, :exit, :exit_group,
          *process_syscalls, *Syscalls.file_changes, *Syscalls::DATAGRAMS, *Syscalls::SUSPICIOUS)
      end
      barrier_reader, barrier_writer = IO.pipe if @cgroup
      supervisor = Seccomp::Notify.spawn(policy, poll_interval: 0.02) do
        Isolation.target_dumpable! if @resolver
        if barrier_reader
          barrier_writer.close
          exit! 126 unless barrier_reader.read(1) == "1"
          barrier_reader.close
        end
        Process.setpgrp
        IO.for_fd(1, autoclose: false).reopen(stdout)
        IO.for_fd(2, autoclose: false).reopen(stderr)
        @resource_limits.each do |resource, limit|
          hard = Process.getrlimit(resource).last
          Process.setrlimit(resource, [limit, hard].min, [limit, hard].min)
        end
        if @enforcement
          begin
            enforcement = @enforcement
            if @isolation == "network_namespace"
              # The namespace launcher writes these once; new namespaces have different proc inodes.
              mappings = %w[uid_map gid_map setgroups].map { |name| "/proc/self/#{name}" }
              enforcement = enforcement.merge(write_paths: enforcement.fetch(:write_paths) + mappings)
            end
            Landlock.restrict!(**enforcement)
          rescue Landlock::Unavailable, ArgumentError => error
            warn "bonebed enforcement failed: #{error.message}"
            exit! 126
          end
        end
        exec(@env, [@command.first, @command.first], *@command.drop(1), chdir: @cwd, unsetenv_others: @unsetenv_others)
      end
      @target_pid = supervisor.target_pid
      if barrier_writer
        barrier_reader.close
        begin
          @cgroup.attach(supervisor.target_pid)
          @collector.cleanup_metadata = {"mode" => "cgroup_v2", "completed" => nil,
                                         "limitation" => "cgroup migration remains possible when the target can write cgroup controls"}
        rescue Cgroup::Unavailable => error
          record_cleanup_fallback(error)
        ensure
          barrier_writer.write("1")
          barrier_writer.close
        end
      end
      open_syscalls.each { |syscall| on(supervisor, syscall) { |request| handle_open(request, syscall) } }
      on(supervisor, :connect) { |request| handle_connect(request) }
      socket_syscalls.each do |syscall|
        on(supervisor, syscall) do |request|
          observe(request, syscall) do
            family, type, protocol = request.args.first(3)
            family &= 0xffffffff
            name = {1 => "unix", 2 => "inet", 10 => "inet6"}.merge(Decoder::Connect::FAMILY_NAMES).fetch(family, "af_#{family}")
            event = {family: name, type: type & 0xf, protocol:}
            @collector.record(:sockets, event)
            trace_fields(request, event)
            deny_event(request, :sockets, event)
            request.error!(Errno::EAFNOSUPPORT) if @resolver && family == Socket::AF_UNIX && !request.responded?
          end
        end
      end
      on(supervisor, :openat2) { |request| handle_openat2(request) }
      on(supervisor, :execve) { |request| handle_execve(request) }
      on(supervisor, :execveat) { |request| handle_execveat(request) }
      Syscalls.file_changes.each { |syscall| on(supervisor, syscall) { |request| handle_file_change(request, syscall) } }
      Syscalls::DATAGRAMS.each { |syscall| on(supervisor, syscall) { |request| handle_datagram(request, syscall) } }
      Syscalls::SUSPICIOUS.each { |syscall| on(supervisor, syscall) { |request| handle_suspicious(request, syscall) } }
      on(supervisor, :bind) { |request| handle_bind(request) }
      on(supervisor, :listen) { |request| handle_listen(request) }
      process_syscalls.each { |syscall| on(supervisor, syscall) { |request| handle_clone(request, syscall) } }
      %i[setsid exit exit_group].each { |syscall| on(supervisor, syscall) { |request| handle_lifetime(request, syscall) } }
      supervisor.on_error { |error, request| @collector.record_observer_error(request&.syscall || "supervisor", error) }
      configured = true
      supervisor
    ensure
      [barrier_reader, barrier_writer].compact.each { |io| io.close unless io.closed? }
      if supervisor && !configured
        terminate(supervisor.target_pid)
        @target_pid = nil
        supervisor.stop
        supervisor.run
      end
    end

    def on(supervisor, syscall)
      supervisor.on(syscall) do |request|
        metadata = task_info(request)
        @trace_fields[request.object_id] = {} if @trace_io
        begin
          yield request
        ensure
          write_trace(request, syscall, metadata) if @trace_io
        end
      end
    end

    def task_info(request)
      metadata = @tasks[request.pid] ||= begin
        status = File.read("/proc/#{request.pid}/status")
        tgid = status[/^Tgid:\s+(\d+)/, 1].to_i
        ppid = @parents[tgid] || status[/^PPid:\s+(\d+)/, 1].to_i
        info = Isolation.process_info(tgid)
        if info && tgid != @target_pid && request.valid?
          @tracking_mutex.synchronize { @tracked[tgid] = info.fetch(:started_at) }
        end
        @executables[tgid] ||= File.readlink("/proc/#{tgid}/exe")
        {tid: request.pid, tgid:, ppid:}
      end
      cwd = begin
        File.readlink("/proc/#{request.pid}/cwd")
      rescue SystemCallError
        nil
      end
      tgid, ppid = metadata.values_at(:tgid, :ppid)
      @collector.record_process({pid: tgid, ppid:, path: @executables[tgid], parent: @executables[ppid], cwd:})
      metadata.merge(cwd:)
    rescue SystemCallError
      {tid: request.pid, tgid: request.pid, ppid: nil}
    end

    def trace_fields(request, event)
      @trace_fields[request.object_id]&.merge!(event)
    end

    def deny_event(request, field, event)
      return unless @deny_policy && !request.responded?
      violations = @deny_policy.violations(field, event)
      return if violations.empty?

      request.error!(Errno::EPERM)
      violations.each do |finding|
        @collector.record_denial({syscall: request.syscall.to_s, capability: finding.fetch("capability"),
                                 rule_id: finding.fetch("rule_id"), severity: finding.fetch("severity")})
      end
      trace_fields(request, {denied: true, deny_rules: violations.map { |finding| finding.fetch("rule_id") }.uniq})
    end

    def deny_open(request, event, flags)
      deny_event(request, :files, event)
      if event[:mode] == :write && (flags & File::WRONLY).zero?
        deny_event(request, :files, event.merge(mode: :read))
      end
    end

    def write_trace(request, syscall, metadata)
      event = @trace_fields.delete(request.object_id) || {}
      event = event.to_h do |key, value|
        value = @trace_normalizer.call(value) if %i[path from to parent].include?(key) && value.is_a?(String) && !(key == :from && event[:symbolic])
        value = value.map { |argument| @trace_normalizer.scrub(argument) } if key == :argv
        if key == :messages
          value = value.map { |message| message[:path] ? message.merge(path: @trace_normalizer.call(message[:path])) : message }
        end
        [key, value]
      end
      metadata = metadata.merge(cwd: @trace_normalizer.call(metadata[:cwd])) if metadata[:cwd]
      row = metadata.merge(t: Process.clock_gettime(Process::CLOCK_MONOTONIC) - @started_at, syscall: syscall.to_s).merge(event)
      row = @redactor.redact(row) if @redactor
      @trace_io.puts(JSON.generate(row))
    rescue => error
      @collector.record_observer_error(:trace, error)
    end

    def remember_exec(request, event, record: true)
      metadata = task_info(request)
      pid = metadata.fetch(:tgid)
      @executables[pid] = File.readlink("/proc/#{pid}/exe")
      path = Decoder::Openat.resolve(event.fetch(:path), request, :open, @cwd)
      begin
        path = File.realpath(path)
      rescue SystemCallError
        nil
      end
      event = event.merge(parent: record ? @executables[pid] : nil)
      @collector.record_exec(event) if record
      @collector.record_process({pid:, ppid: metadata[:ppid], path:, parent: event[:parent], cwd: metadata[:cwd]})
      @executables[pid] = path
      trace_fields(request, event)
    end

    def track_descendants(pid)
      descendants = Isolation.descendants(pid)
      descendants.each_key { |child| @parents[child] ||= Isolation.process_info(child)&.fetch(:parent) }
      @tracking_mutex.synchronize { @tracked.merge!(descendants) }
    end

    def watch_root
      identity = Isolation.process_info(@target_pid)&.fetch(:started_at)
      @watching = true
      Thread.new do
        while @watching
          if Isolation.process_info(@target_pid)&.fetch(:started_at) != identity
            cleanup_descendants
            break
          end
          sleep 0.02
        end
      rescue => error
        @collector.record_observer_error(:cleanup, error)
      end
    end

    def cleanup_descendants
      @cleanup_mutex.synchronize do
        if @cgroup && !@cgroup_cleaned
          result = @cgroup.kill(timeout: 1)
          @cgroup_cleaned = true
          @tracking_mutex.synchronize { @tracked.merge!(result.processes.except(@target_pid)) }
          result.errors.each { |message| @collector.record_observer_error(:cleanup, Error.new(message)) }
          @collector.cleanup_metadata["completed"] = result.errors.empty? if @collector.cleanup_metadata&.fetch("mode") == "cgroup_v2"
        end
        tracked = @tracking_mutex.synchronize { @tracked.dup }
        Isolation.cleanup(tracked).each { |message| @collector.record_observer_error(:cleanup, Error.new(message)) }
      end
    end

    def record_cleanup_fallback(error)
      @collector.cleanup_metadata = {"mode" => "tracked", "completed" => nil,
                                     "limitation" => "#{error.message}; an unobserved fork/reparent race may escape tracked cleanup"}
    end

    def handle_lifetime(request, syscall)
      observe(request, syscall) do
        metadata = task_info(request)
        track_descendants(metadata.fetch(:tgid)) if request.valid? && (syscall != :exit || request.pid == metadata[:tgid])
        @tasks.delete(request.pid) if %i[exit exit_group].include?(syscall)
      end
    end

    def stream(reader, destination)
      Thread.new do
        captured = +"".b
        truncated = false
        loop do
          chunk = reader.readpartial(4096)
          remaining = @output_limit - captured.bytesize
          truncated ||= chunk.bytesize > remaining
          captured << chunk.byteslice(0, remaining) if remaining.positive?
          mirror(destination, chunk) unless @quiet_target
        end
      rescue IOError, Errno::EBADF
        {text: captured, truncated:}
      ensure
        reader.close unless reader.closed?
      end
    end

    def output(stdout_thread, stderr_thread)
      stdout = stdout_thread&.value || {text: "", truncated: false}
      stderr = stderr_thread&.value || {text: "", truncated: false}
      {stdout: stdout[:text], stderr: stderr[:text], stdout_truncated: stdout[:truncated], stderr_truncated: stderr[:truncated]}
    end

    def mirror(destination, chunk)
      destination.write(chunk)
      destination.flush
    rescue IOError, SystemCallError
      nil
    end

    def handle_open(request, syscall)
      @collector.record_notification
      event = Decoder::Openat.call(request, syscall:, cwd: @cwd)
      trace_fields(request, event)
      # ponytail: same-mount check drops failed read probes; retain attempts if targets gain separate mounts.
      @collector.record_open(event) if (!@writes_only || event[:mode] != :read) && !discardable_probe?(event)
      flags = request.args.fetch((syscall == :open) ? 1 : 2)
      record_write_kinds(event[:path], flags, request)
      deny_open(request, event, flags)
      inject_resolver(request, event[:path], flags) unless request.responded?
    rescue => error
      @collector.record_observer_error(syscall, error)
    ensure
      request.continue!(unsafe: true) unless request.responded?
    end

    def discardable_probe?(event)
      path = event[:path]
      return false unless event[:mode] == :read && path.start_with?(File::SEPARATOR)
      return false if SensitivePath.match?(path, home: @env.fetch("HOME", Dir.home), cwd: @cwd)

      !File.exist?(path)
    end

    def inject_resolver(request, path, flags)
      return unless @resolver && path == "/etc/resolv.conf"

      if (flags & (File::WRONLY | File::RDWR | File::CREAT | File::TRUNC | File::APPEND)).positive?
        request.error!(Errno::EACCES)
      elsif (flags & 0x10000).positive? # O_DIRECTORY
        request.error!(Errno::ENOTDIR)
      else
        # Reopen the pinned inode so each injected descriptor has an independent offset.
        File.open("/proc/self/fd/#{@resolver.fileno}", "rb") do |file|
          request.add_fd!(file, newfd_flags: flags & 0x80000)
        end
      end
    rescue
      request.error!(Errno::EIO) unless request.responded?
      raise
    end

    def record_write_kinds(path, flags, request)
      {create: File::CREAT, truncate: File::TRUNC, append: File::APPEND, rw: File::RDWR}.each do |operation, flag|
        next unless (flags & flag).positive?
        @collector.record(:changes, {operation:, path:})
        deny_event(request, :changes, {operation:, path:})
      end
    end

    def handle_connect(request)
      decoded = false
      @collector.record_notification
      raise ArgumentError, "invalid sockaddr length" unless (2..Decoder::Connect::MAX_LENGTH).cover?(request.args.fetch(2))

      bytes = request.read(request.args.fetch(1), request.args.fetch(2))
      event = Decoder::Connect.call(bytes)
      decoded = true
      trace_fields(request, event || {})
      identity = socket_identity(request, request.args.fetch(0))
      if event
        @collector.record_network(event)
        deny_event(request, :network, event)
        @endpoints[identity] = event if identity
      elsif identity
        @endpoints.delete(identity)
      end
    rescue => error
      @collector.record_observer_error(:connect, error)
    ensure
      unless request.responded?
        (@offline || (@resolver && (!decoded || event&.fetch(:family) == "unix"))) ? request.error!(Errno::ENETUNREACH) : request.continue!(unsafe: true)
      end
    end

    def handle_execve(request)
      @collector.record_notification
      event = Decoder::Execve.call(request, limit: @argv_limit)
      event[:path] = Decoder::Openat.resolve(event[:path], request, :open, @cwd)
      event[:env_keys] = Decoder::Execve.read_arguments(request, request.args.fetch(2), limit: 256).first.map { |value| value.split("=", 2).first }.uniq.sort
      if @bootstrap_remaining.positive?
        @bootstrap_remaining -= 1
        remember_exec(request, event, record: false)
      elsif File.executable?(event[:path])
        # ponytail: same-mount check filters failed PATH lookups; retain attempts if targets gain separate mounts.
        remember_exec(request, event)
        deny_event(request, :exec, event)
      end
    rescue => error
      @collector.record_observer_error(:execve, error)
    ensure
      request.continue!(unsafe: true) unless request.responded?
    end

    def handle_clone(request, syscall)
      @collector.record_notification
      event = Decoder::Clone.call(request, syscall:) unless %i[fork vfork].include?(syscall)
      event ? @collector.record_thread(event) : @collector.record(:processes, {syscall: syscall.to_s})
      trace_fields(request, {kind: event ? "thread" : "process"})
      deny_event(request, event ? :threads : :processes, event || {syscall: syscall.to_s})
      track_descendants(process_id(request)) if !event && request.valid?
    rescue => error
      @collector.record_observer_error(syscall, error)
    ensure
      request.continue!(unsafe: syscall == :clone3) unless request.responded?
    end

    def process_id(request)
      task_info(request).fetch(:tgid)
    end

    def socket_identity(request, fd)
      value = File.readlink("/proc/#{request.pid}/fd/#{fd}")
      value if value.start_with?("socket:[")
    rescue SystemCallError
      nil
    end

    def observe(request, syscall)
      @collector.record_notification
      yield
    rescue => error
      @collector.record_observer_error(syscall, error)
    ensure
      request.continue!(unsafe: true) unless request.responded?
    end

    def handle_file_change(request, syscall)
      observe(request, syscall) do
        event = Decoder::FileChange.call(request, syscall:, cwd: @cwd)
        trace_fields(request, event)
        @collector.record(:changes, event)
        deny_event(request, :changes, event)
      end
    end

    def handle_openat2(request)
      observe(request, :openat2) do
        raise ArgumentError, "short open_how" if request.args.fetch(3) < 8

        flags = request.read(request.args.fetch(2), 8).unpack1("Q<")
        path = Decoder::Openat.resolve(request.read_string(request.args.fetch(1)), request, :openat, @cwd)
        write = (flags & (File::WRONLY | File::RDWR | File::CREAT | File::TRUNC | File::APPEND)).positive?
        event = {path:, mode: write ? :write : :read}
        trace_fields(request, event)
        @collector.record_open(event) if (!@writes_only || write) && !discardable_probe?(event)
        record_write_kinds(path, flags, request)
        deny_open(request, event, flags)
        inject_resolver(request, path, flags) unless request.responded?
      end
    end

    def handle_execveat(request)
      observe(request, :execveat) do
        path = Decoder::Openat.resolve(request.read_string(request.args.fetch(1)), request, :openat, @cwd)
        @collector.record(:suspicious, {syscall: "execveat", path:})
        argv, truncated = Decoder::Execve.read_arguments(request, request.args.fetch(2), limit: @argv_limit)
        env_keys = Decoder::Execve.read_arguments(request, request.args.fetch(3), limit: 256).first.map { |value| value.split("=", 2).first }.uniq.sort
        remember_exec(request, {path:, argv:, argv_truncated: truncated, env_keys:, syscall: "execveat"})
        deny_event(request, :exec, {path:, argv:, syscall: "execveat"})
      end
    end

    def handle_suspicious(request, syscall)
      observe(request, syscall) do
        if syscall == :kill
          handle_kill(request)
        elsif syscall == :unshare && @namespace_bootstrap
          @namespace_bootstrap = false
        else
          @collector.record(:suspicious, {syscall: syscall.to_s})
          deny_event(request, :suspicious, {syscall: syscall.to_s})
        end
        request.error!(Errno::ENOSYS) if syscall == :io_uring_setup && !request.responded?
      end
    end

    def handle_kill(request)
      pid, signal = request.args.first(2).map { |value| [value & 0xffffffff].pack("L").unpack1("l") }
      trace_fields(request, {target_pid: pid, signal:, probe: signal.zero?})
      return if signal.zero? || own_signal_target?(request, pid)

      target = if pid.positive?
        "<pid>"
      elsif pid.zero?
        "current_process_group"
      elsif pid == -1
        "all"
      else
        "<pgid>"
      end
      event = {syscall: "kill", signal:, target_pid: target}
      @collector.record(:suspicious, event)
      deny_event(request, :suspicious, event)
    end

    def own_signal_target?(request, pid)
      return false unless pid.positive?
      caller = process_id(request)
      return true if pid == caller
      status = File.read("/proc/#{pid}/status")
      status[/^Tgid:\s+(\d+)/, 1].to_i == caller
    rescue SystemCallError
      false
    end

    def handle_bind(request)
      observe(request, :bind) do
        raise ArgumentError, "invalid sockaddr length" unless (2..Decoder::Connect::MAX_LENGTH).cover?(request.args.fetch(2))

        event = Decoder::Connect.call(request.read(request.args.fetch(1), request.args.fetch(2)))
        trace_fields(request, event || {})
        identity = socket_identity(request, request.args.fetch(0))
        @bindings[identity] = event if event && identity
        @collector.record(:listen, event.merge(syscall: "bind")) if event
        deny_event(request, :listen, event) if event
      end
    end

    def handle_listen(request)
      observe(request, :listen) do
        event = @bindings[socket_identity(request, request.args.fetch(0))] || {family: "unknown"}
        trace_fields(request, event)
        @collector.record(:listen, event.merge(syscall: "listen"))
        deny_event(request, :listen, event)
      end
    end

    def handle_datagram(request, syscall)
      decoded = false
      @collector.record_notification
      messages = []
      Decoder::Datagram.call(request, syscall:).each do |message|
        event = message[:destination] || @endpoints[socket_identity(request, message[:fd])]
        next unless event

        @collector.record_network(event)
        deny_event(request, :network, event)
        messages << event.merge(fd: message[:fd])
        if event[:port] == 53
          Decoder::DNS.questions(message[:payload]).each do |name|
            @collector.record(:dns, {name:})
            deny_event(request, :dns, {name:})
          end
        end
      end
      trace_fields(request, {messages:})
      decoded = true
    rescue => error
      @collector.record_observer_error(syscall, error)
    ensure
      unless request.responded?
        (@offline || (@resolver && (!decoded || messages.any? { |event| event[:family] == "unix" }))) ? request.error!(Errno::ENETUNREACH) : request.continue!(unsafe: true)
      end
    end

    def terminate(pid)
      return unless pid

      begin
        Process.kill("KILL", -pid)
      rescue Errno::ESRCH
        Process.kill("KILL", pid)
      end
      Process.waitpid(pid)
    rescue Errno::ECHILD, Errno::ESRCH
      nil
    end
  end
end
