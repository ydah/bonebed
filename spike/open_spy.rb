# frozen_string_literal: true

require "seccomp/notify"

open_syscalls = RUBY_PLATFORM.include?("x86_64") ? %i[open openat] : %i[openat]
policy = Seccomp::Notify::Policy.new { notify(*open_syscalls) }
supervisor = Seccomp::Notify.spawn(policy) { exec(RbConfig.ruby, "-e", 'File.read("/etc/hostname")') }
count = 0

open_syscalls.each do |syscall|
  supervisor.on(syscall) do |request|
    argument = syscall == :open ? 0 : 1
    warn "#{syscall} #{request.read_string(request.args[argument])}"
    count += 1
    request.continue!(unsafe: true)
  end
end

status = supervisor.run
warn "open calls: #{count}"
exit(status.exitstatus)
