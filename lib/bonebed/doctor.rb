# frozen_string_literal: true

require "rbconfig"
require "bundler"

module Bonebed
  class Doctor
    SUPPORTED_ARCHES = %w[x86_64 aarch64].freeze

    def initialize(output: $stdout)
      @output = output
    end

    def self.container?
      return true if File.exist?("/.dockerenv") || File.exist?("/run/.containerenv")

      File.read("/proc/1/cgroup").match?(/docker|containerd|kubepods|libpod|lxc/)
    rescue SystemCallError
      false
    end

    def run
      features = seccomp_features
      checks = [
        ["kernel", kernel_release, linux? && kernel_supported?],
        ["arch", arch, linux? && SUPPORTED_ARCHES.include?(arch)],
        ["CONFIG_SECCOMP_FILTER", config_status(features), features[:user_notif]],
        ["SECCOMP_RET_USER_NOTIF", enabled(features[:user_notif]), features[:user_notif]],
        ["continue (5.5+)", enabled(features[:continue]), features[:continue]],
        ["addfd (5.9+)", enabled(features[:addfd]), features[:addfd]],
        ["container seccomp profile", container_status, true]
      ]
      checks.each { |name, value, ok| @output.puts(format("%-30s %-24s %s", name, value, ok ? "OK" : "NG")) }
      {
        "Ruby" => RUBY_VERSION,
        "RubyGems" => Gem::VERSION,
        "Bundler" => Bundler::VERSION,
        "user namespaces (max)" => read_setting("/proc/sys/user/max_user_namespaces"),
        "AppArmor userns restriction" => read_setting("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
        "cgroup v2" => enabled(File.exist?("/sys/fs/cgroup/cgroup.controllers")),
        "container (heuristic)" => self.class.container? ? "detected" : "not detected"
      }.each { |name, value| @output.puts(format("%-30s %s", name, value)) }
      checks.first(6).all?(&:last)
    end

    private

    def read_setting(path)
      File.read(path).strip
    rescue SystemCallError
      "unavailable"
    end

    def linux?
      RUBY_PLATFORM.include?("linux")
    end

    def kernel_release
      `uname -r`.strip
    end

    def kernel_supported?
      Gem::Version.new(kernel_release[/\A\d+(?:\.\d+)+/] || "0") >= Gem::Version.new("5.5")
    end

    def arch
      RbConfig::CONFIG.fetch("host_cpu").sub("arm64", "aarch64")
    end

    def seccomp_features
      return {} unless linux?

      require "seccomp/notify"
      Seccomp::Notify.features
    rescue LoadError, StandardError
      {}
    end

    def enabled(value)
      value ? "available" : "unavailable"
    end

    def config_status(features)
      return "enabled" if features[:user_notif]

      linux? ? "unavailable" : "Linux only"
    end

    def container_status
      return "not Linux" unless linux?

      mode = File.read("/proc/self/status")[/^Seccomp:\s+(\d+)/, 1]
      (mode == "0") ? "unconfined" : "filter active"
    rescue SystemCallError
      "unknown"
    end
  end
end
