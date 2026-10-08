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

module Bonebed
  class Session
    OUTPUT_LIMIT = 1 << 20

    def initialize(command, env: {}, cwd: Dir.pwd, timeout: 30, offline: false, collector: Collector.new,
      output_limit: OUTPUT_LIMIT, argv_limit: 64, quiet_target: false, target_stdout: $stdout, unsetenv_others: false,
      writes_only: false, trace: nil, enforcement: nil, resource_limits: {}, redactor: nil)
      raise ArgumentError, "timeout must be positive" unless timeout.is_a?(Numeric) && timeout.positive?
      raise ArgumentError, "output limit must be nonnegative" unless output_limit.is_a?(Integer) && output_limit >= 0
      raise ArgumentError, "argv limit must be positive" unless argv_limit.is_a?(Integer) && argv_limit.positive?
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
      @timeout = timeout
      @offline = offline
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
      terminate(supervisor&.target_pid) if supervisor && !status && !terminated
      @watching = false
      watcher&.join
      cleanup_descendants
      [stdout_reader, stdout_writer, stderr_reader, stderr_writer].compact.each { |io| io.close unless io.closed? }
      [stdout_thread, stderr_thread].compact.each(&:join)
      @trace_io&.close
    end

    private

    def build_supervisor(stdout, stderr)
      require "seccomp/notify"
      open_syscalls = RUBY_PLATFORM.include?("x86_64") ? %i[open openat] : %i[openat]
      process_syscalls = RUBY_PLATFORM.include?("x86_64") ? %i[clone clone3 fork vfork] : %i[clone clone3]
      writes_only = @writes_only
      policy = Seccomp::Notify::Policy.new(deny_io_uring: false) do
        if writes_only
          open_syscalls.each do |syscall|
            notify_if(syscall, argument: (syscall == :open) ? 1 : 2, mask: File::WRONLY | File::RDWR | File::CREAT | File::TRUNC | File::APPEND)
          end
        else
          notify(*open_syscalls)
        end
        notify(:openat2, :socket, :connect, :execve, :execveat, :bind, :listen, :setsid, :exit, :exit_group,
          *process_syscalls, *Syscalls.file_changes, *Syscalls::DATAGRAMS, *Syscalls::SUSPICIOUS)
      end
      supervisor = Seccomp::Notify.spawn(policy, poll_interval: 0.02) do
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
      open_syscalls.each { |syscall| on(supervisor, syscall) { |request| handle_open(request, syscall) } }
      on(supervisor, :connect) { |request| handle_connect(request) }
      on(supervisor, :socket) do |request|
        observe(request, :socket) do
          family, type, protocol = request.args.first(3)
          name = {1 => "unix", 2 => "inet", 10 => "inet6"}.merge(Decoder::Connect::FAMILY_NAMES).fetch(family, "af_#{family}")
          event = {family: name, type: type & 0xf, protocol:}
          @collector.record(:sockets, event)
          trace_fields(request, event)
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
      supervisor
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
      @tasks[request.pid] ||= begin
        status = File.read("/proc/#{request.pid}/status")
        tgid = status[/^Tgid:\s+(\d+)/, 1].to_i
        ppid = @parents[tgid] || status[/^PPid:\s+(\d+)/, 1].to_i
        info = Isolation.process_info(tgid)
        if info && tgid != @target_pid && request.valid?
          @tracking_mutex.synchronize { @tracked[tgid] = info.fetch(:started_at) }
        end
        @executables[tgid] ||= File.readlink("/proc/#{tgid}/exe")
        @collector.record_process({pid: tgid, ppid:, path: @executables[tgid], parent: @executables[ppid]})
        {tid: request.pid, tgid:, ppid:}
      end
    rescue SystemCallError
      {tid: request.pid, tgid: request.pid, ppid: nil}
    end

    def trace_fields(request, event)
      @trace_fields[request.object_id]&.merge!(event)
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
      @collector.record_process({pid:, ppid: metadata[:ppid], path:, parent: event[:parent]})
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
        tracked = @tracking_mutex.synchronize { @tracked.dup }
        # ponytail: unseen fork/reparent races require a delegated cgroup for complete tree cleanup.
        Isolation.cleanup(tracked).each { |message| @collector.record_observer_error(:cleanup, Error.new(message)) }
      end
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
      @collector.record_open(event) unless discardable_probe?(event)
      record_write_kinds(event[:path], request.args.fetch((syscall == :open) ? 1 : 2))
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

    def record_write_kinds(path, flags)
      {create: File::CREAT, truncate: File::TRUNC, append: File::APPEND, rw: File::RDWR}.each do |operation, flag|
        @collector.record(:changes, {operation:, path:}) if (flags & flag).positive?
      end
    end

    def handle_connect(request)
      @collector.record_notification
      raise ArgumentError, "invalid sockaddr length" unless (2..Decoder::Connect::MAX_LENGTH).cover?(request.args.fetch(2))

      bytes = request.read(request.args.fetch(1), request.args.fetch(2))
      event = Decoder::Connect.call(bytes)
      trace_fields(request, event || {})
      identity = socket_identity(request, request.args.fetch(0))
      if event
        @collector.record_network(event)
        @endpoints[identity] = event if identity
      elsif identity
        @endpoints.delete(identity)
      end
    rescue => error
      @collector.record_observer_error(:connect, error)
    ensure
      unless request.responded?
        @offline ? request.error!(Errno::ENETUNREACH) : request.continue!(unsafe: true)
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
        record_write_kinds(path, flags)
      end
    end

    def handle_execveat(request)
      observe(request, :execveat) do
        path = Decoder::Openat.resolve(request.read_string(request.args.fetch(1)), request, :openat, @cwd)
        @collector.record(:suspicious, {syscall: "execveat", path:})
        argv, truncated = Decoder::Execve.read_arguments(request, request.args.fetch(2), limit: @argv_limit)
        env_keys = Decoder::Execve.read_arguments(request, request.args.fetch(3), limit: 256).first.map { |value| value.split("=", 2).first }.uniq.sort
        remember_exec(request, {path:, argv:, argv_truncated: truncated, env_keys:, syscall: "execveat"})
      end
    end

    def handle_suspicious(request, syscall)
      observe(request, syscall) do
        if syscall == :unshare && @namespace_bootstrap
          @namespace_bootstrap = false
        else
          @collector.record(:suspicious, {syscall: syscall.to_s})
        end
        request.error!(Errno::ENOSYS) if syscall == :io_uring_setup
      end
    end

    def handle_bind(request)
      observe(request, :bind) do
        raise ArgumentError, "invalid sockaddr length" unless (2..Decoder::Connect::MAX_LENGTH).cover?(request.args.fetch(2))

        event = Decoder::Connect.call(request.read(request.args.fetch(1), request.args.fetch(2)))
        trace_fields(request, event || {})
        identity = socket_identity(request, request.args.fetch(0))
        @bindings[identity] = event if event && identity
        @collector.record(:listen, event.merge(syscall: "bind")) if event
      end
    end

    def handle_listen(request)
      observe(request, :listen) do
        event = @bindings[socket_identity(request, request.args.fetch(0))] || {family: "unknown"}
        trace_fields(request, event)
        @collector.record(:listen, event.merge(syscall: "listen"))
      end
    end

    def handle_datagram(request, syscall)
      @collector.record_notification
      messages = []
      Decoder::Datagram.call(request, syscall:).each do |message|
        event = message[:destination] || @endpoints[socket_identity(request, message[:fd])]
        next unless event

        @collector.record_network(event)
        messages << event.merge(fd: message[:fd])
        if event[:port] == 53
          Decoder::DNS.questions(message[:payload]).each { |name| @collector.record(:dns, {name:}) }
        end
      end
      trace_fields(request, {messages:})
    rescue => error
      @collector.record_observer_error(syscall, error)
    ensure
      unless request.responded?
        @offline ? request.error!(Errno::ENETUNREACH) : request.continue!(unsafe: true)
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
