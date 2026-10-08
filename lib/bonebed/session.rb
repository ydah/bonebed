# frozen_string_literal: true

require "timeout"
require_relative "collector"
require_relative "sensitive_path"
require_relative "decoder/openat"
require_relative "decoder/connect"
require_relative "decoder/execve"
require_relative "decoder/clone"

module Bonebed
  class Session
    def initialize(command, env: {}, cwd: Dir.pwd, timeout: 30, offline: false, collector: Collector.new)
      @command = command
      @env = env
      @cwd = cwd
      @timeout = timeout
      @offline = offline
      @collector = collector
      @bootstrap_exec = true
    end

    def run
      started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      stdout_reader, stdout_writer = IO.pipe
      stderr_reader, stderr_writer = IO.pipe
      supervisor = build_supervisor(stdout_writer, stderr_writer)
      stdout_writer.close
      stderr_writer.close
      stdout_thread = stream(stdout_reader, $stdout)
      stderr_thread = stream(stderr_reader, $stderr)
      status = Timeout.timeout(@timeout) { supervisor.run }
      @collector.finish(started_at, status, stdout: stdout_thread.value, stderr: stderr_thread.value)
      @collector
    rescue Timeout::Error
      terminate(supervisor&.target_pid)
      terminated = true
      @collector.record_error("session", Timeout::Error.new("timed out after #{@timeout} seconds"))
      @collector.finish(started_at, nil, stdout: stdout_thread&.value.to_s, stderr: stderr_thread&.value.to_s)
      @collector
    ensure
      terminate(supervisor&.target_pid) if supervisor && !status && !terminated
      [stdout_reader, stdout_writer, stderr_reader, stderr_writer].compact.each { |io| io.close unless io.closed? }
      [stdout_thread, stderr_thread].compact.each(&:join)
    end

    private

    def build_supervisor(stdout, stderr)
      require "seccomp/notify"
      open_syscalls = RUBY_PLATFORM.include?("x86_64") ? %i[open openat] : %i[openat]
      policy = Seccomp::Notify::Policy.new { notify(*open_syscalls, :connect, :execve, :clone, :clone3) }
      supervisor = Seccomp::Notify.spawn(policy) do
        Process.setpgrp
        STDOUT.reopen(stdout)
        STDERR.reopen(stderr)
        exec(@env, *@command, chdir: @cwd)
      end
      open_syscalls.each { |syscall| supervisor.on(syscall) { |request| handle_open(request, syscall) } }
      supervisor.on(:connect) { |request| handle_connect(request) }
      supervisor.on(:execve) { |request| handle_execve(request) }
      %i[clone clone3].each { |syscall| supervisor.on(syscall) { |request| handle_clone(request, syscall) } }
      supervisor.on_error { |error, request| @collector.record_error(request&.syscall || "supervisor", error) }
      supervisor
    end

    def stream(reader, destination)
      Thread.new do
        captured = +""
        loop do
          chunk = reader.readpartial(4096)
          captured << chunk
          mirror(destination, chunk)
        end
      rescue EOFError, IOError, Errno::EBADF
        captured
      ensure
        reader.close unless reader.closed?
      end
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
      # ponytail: same-mount check drops failed read probes; retain attempts if targets gain separate mounts.
      @collector.record_open(event) unless discardable_probe?(event)
    rescue StandardError => error
      @collector.record_error(syscall, error)
    ensure
      request.continue!(unsafe: true) unless request.responded?
    end

    def discardable_probe?(event)
      path = event[:path]
      return false unless event[:mode] == :read && path.start_with?(File::SEPARATOR)
      return false if SensitivePath.match?(path, home: @env.fetch("HOME", Dir.home), cwd: @cwd)

      !File.exist?(path)
    end

    def handle_connect(request)
      @collector.record_notification
      bytes = request.read(request.args.fetch(1), request.args.fetch(2))
      event = Decoder::Connect.call(bytes)
      @collector.record_network(event) if event
    rescue StandardError => error
      @collector.record_error(:connect, error)
    ensure
      unless request.responded?
        @offline ? request.error!(Errno::ENETUNREACH) : request.continue!(unsafe: true)
      end
    end

    def handle_execve(request)
      @collector.record_notification
      if @bootstrap_exec
        @bootstrap_exec = false
      else
        event = Decoder::Execve.call(request)
        # ponytail: same-mount check filters failed PATH lookups; retain attempts if targets gain separate mounts.
        @collector.record_exec(event) if File.executable?(event[:path])
      end
    rescue StandardError => error
      @collector.record_error(:execve, error)
    ensure
      request.continue!(unsafe: true) unless request.responded?
    end

    def handle_clone(request, syscall)
      @collector.record_notification
      event = Decoder::Clone.call(request, syscall:)
      @collector.record_thread(event) if event
    rescue StandardError => error
      @collector.record_error(syscall, error)
    ensure
      request.continue!(unsafe: syscall == :clone3) unless request.responded?
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
