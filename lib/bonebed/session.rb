# frozen_string_literal: true

require "timeout"
require_relative "collector"
require_relative "decoder/openat"
require_relative "decoder/connect"
require_relative "decoder/execve"

module Bonebed
  class Session
    def initialize(command, env: {}, timeout: 30, offline: false, collector: Collector.new)
      @command = command
      @env = env
      @timeout = timeout
      @offline = offline
      @collector = collector
      @bootstrap_exec = true
    end

    def run
      started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      supervisor = build_supervisor
      status = Timeout.timeout(@timeout) { supervisor.run }
      @collector.finish(started_at, status)
      @collector
    rescue Timeout::Error
      terminate(supervisor&.target_pid)
      @collector.record_error("session", Timeout::Error.new("timed out after #{@timeout} seconds"))
      @collector.finish(started_at, nil)
      @collector
    end

    private

    def build_supervisor
      require "seccomp/notify"
      open_syscalls = RUBY_PLATFORM.include?("x86_64") ? %i[open openat] : %i[openat]
      policy = Seccomp::Notify::Policy.new { notify(*open_syscalls, :connect, :execve) }
      supervisor = Seccomp::Notify.spawn(policy) { exec(@env, *@command) }
      open_syscalls.each { |syscall| supervisor.on(syscall) { |request| handle_open(request, syscall) } }
      supervisor.on(:connect) { |request| handle_connect(request) }
      supervisor.on(:execve) { |request| handle_execve(request) }
      supervisor.on_error { |error, request| @collector.record_error(request&.syscall || "supervisor", error) }
      supervisor
    end

    def handle_open(request, syscall)
      @collector.record_notification
      @collector.record_open(Decoder::Openat.call(request, syscall:))
    rescue StandardError => error
      @collector.record_error(syscall, error)
    ensure
      request.continue!(unsafe: true) unless request.responded?
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
        @collector.record_exec(Decoder::Execve.call(request))
      end
    rescue StandardError => error
      @collector.record_error(:execve, error)
    ensure
      request.continue!(unsafe: true) unless request.responded?
    end

    def terminate(pid)
      return unless pid

      Process.kill("KILL", pid)
      Process.waitpid(pid)
    rescue Errno::ECHILD, Errno::ESRCH
      nil
    end
  end
end
