# frozen_string_literal: true

require "securerandom"
require_relative "isolation"

module Bonebed
  class Cgroup
    class Unavailable < StandardError; end
    Result = Struct.new(:processes, :errors)
    attr_reader :path

    def self.delegated_directory(membership: File.read("/proc/self/cgroup"), mounts: File.read("/proc/self/mountinfo"))
      current = membership.lines.filter_map { |line| line.strip.delete_prefix("0::") if line.start_with?("0::") }.first
      raise Unavailable, "no unified cgroup membership" unless current&.start_with?("/") && !current.split("/").include?("..")

      mounts.lines.filter_map do |line|
        fields, filesystem = line.split(" - ", 2)
        next unless filesystem&.split&.first == "cgroup2"

        root, mount = fields.split.values_at(3, 4).map { |value| value.gsub(/\\([0-7]{3})/) { Regexp.last_match(1).to_i(8).chr } }
        next unless current == root || root == "/" || current.start_with?("#{root}/")

        relative = (root == "/") ? current : current.delete_prefix(root)
        File.join(mount, relative.delete_prefix("/"))
      end.first || raise(Unavailable, "current cgroup has no visible v2 mount")
    rescue SystemCallError => error
      raise Unavailable, "cgroup v2 unavailable: #{error.message}"
    end

    def self.create(parent: nil)
      raise Unavailable, "cgroup v2 requires Linux" unless RUBY_PLATFORM.include?("linux")

      new(parent || delegated_directory)
    rescue SystemCallError => error
      raise Unavailable, "cgroup delegation unavailable: #{error.message}"
    end

    def initialize(parent)
      parent = File.realpath(parent)
      unless File.file?(File.join(parent, "cgroup.controllers")) && File.writable?(parent) && File.writable?(File.join(parent, "cgroup.procs"))
        raise Unavailable, "current cgroup is not writable and delegated"
      end
      @path = File.join(parent, "bonebed-#{Process.pid}-#{SecureRandom.hex(12)}")
      Dir.mkdir(@path, 0o700)
      @directory = File.open(@path, File::RDONLY | File::NOFOLLOW)
      @identity = [@directory.stat.dev, @directory.stat.ino]
      raise Unavailable, "target cgroup is not a domain" unless read_control("cgroup.type").strip == "domain"
      raise Unavailable, "new target cgroup is already populated" unless read_control("cgroup.procs").strip.empty?

      %w[cgroup.procs cgroup.kill].each do |name|
        File.open(control(name), File::WRONLY | File::NOFOLLOW, &:close)
      end
      read_control("cgroup.events")
    rescue SystemCallError, Unavailable
      close
      raise
    end

    def attach(pid)
      raise Unavailable, "only a direct target child can enter its cgroup" unless pid.is_a?(Integer) && pid.positive? && pid != Process.pid

      info = Isolation.process_info(pid)
      raise Unavailable, "only a direct target child can enter its cgroup" unless info && info[:parent] == Process.pid

      write_control("cgroup.procs", pid.to_s)
      raise Unavailable, "target cgroup attachment was not confirmed" unless read_control("cgroup.procs").lines.map(&:to_i).include?(pid)
    rescue SystemCallError => error
      raise Unavailable, "target cgroup attachment failed: #{error.message}"
    end

    def kill(timeout: 1)
      return @result if @result

      @processes ||= {}
      result = Result.new(processes: @processes, errors: [])
      deadline = monotonic + timeout
      begin
        collect_processes("/proc/self/fd/#{@directory.fileno}", deadline, result.processes)
      rescue SystemCallError, Unavailable => error
        result.errors << "cgroup process enumeration incomplete: #{error.message}"
      end
      if result.processes.key?(Process.pid)
        result.errors << "refusing to kill cgroup containing the supervisor"
        return @result = result
      end
      write_control("cgroup.kill", "1")
      wait_value("populated", 0, deadline)
      @result = result
    rescue SystemCallError, Unavailable => error
      result.errors << "cgroup cleanup incomplete: #{error.message}"
      @result = result
    end

    def close
      return [] unless @directory

      errors = []
      begin
        stat = File.stat(@path)
        if [stat.dev, stat.ino] == @identity
          remove_descendants(@directory, monotonic + 1) if @result&.errors&.empty?
          Dir.rmdir(@path)
        else
          errors << "cgroup directory was replaced; leaving replacement untouched"
        end
      rescue Errno::ENOENT
        nil
      rescue SystemCallError, Unavailable => error
        errors << "could not remove target cgroup: #{error.message}"
      ensure
        @directory.close unless @directory.closed?
        @directory = nil
      end
      errors
    end

    private

    def control(name)
      "/proc/self/fd/#{@directory.fileno}/#{name}"
    end

    def read_control(name)
      File.open(control(name), File::RDONLY | File::NOFOLLOW, &:read)
    end

    def write_control(name, value)
      File.open(control(name), File::WRONLY | File::NOFOLLOW) { |file| file.write(value) }
    end

    def monotonic
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    def wait_value(key, value, deadline)
      loop do
        values = read_control("cgroup.events").lines.map(&:split).to_h
        return if values[key] == value.to_s
        raise Unavailable, "waiting for cgroup #{key}=#{value} timed out" if monotonic >= deadline

        sleep 0.01
      end
    end

    def collect_processes(directory, deadline, processes, remaining = [256])
      remaining[0] -= 1
      raise Unavailable, "cgroup process enumeration limit reached" if remaining[0].negative? || monotonic >= deadline

      File.open(File.join(directory, "cgroup.procs"), File::RDONLY | File::NOFOLLOW) do |file|
        file.each_line do |line|
          pid = Integer(line.strip)
          info = Isolation.process_info(pid)
          processes[pid] = info[:started_at] if info
        end
      end
      Dir.children(directory).each do |name|
        child = File.join(directory, name)
        raise Unavailable, "unexpected symlink in target cgroup" if File.symlink?(child)

        collect_processes(child, deadline, processes, remaining) if File.directory?(child)
      end
    end

    def remove_descendants(directory, deadline, remaining = [256])
      remaining[0] -= 1
      raise Unavailable, "cgroup directory removal limit reached" if remaining[0].negative? || monotonic >= deadline

      Dir.children("/proc/self/fd/#{directory.fileno}").each do |name|
        path = "/proc/self/fd/#{directory.fileno}/#{name}"
        stat = File.lstat(path)
        raise Unavailable, "unexpected symlink in target cgroup" if stat.symlink?
        next unless stat.directory?

        File.open(path, File::RDONLY | File::NOFOLLOW) do |child|
          raise Unavailable, "target cgroup directory was replaced" unless [child.stat.dev, child.stat.ino] == [stat.dev, stat.ino]

          remove_descendants(child, deadline, remaining)
          current = File.lstat(path)
          raise Unavailable, "target cgroup directory was replaced" unless [current.dev, current.ino] == [stat.dev, stat.ino]

          Dir.rmdir(path)
        end
      end
    end
  end
end
