# frozen_string_literal: true

require "rbconfig"

module Bonebed
  module Syscalls
    COMMON_FILE_CHANGES = %i[unlinkat renameat renameat2 mkdirat symlinkat linkat fchmod fchmodat fchmodat2 fchown fchownat truncate ftruncate].freeze
    LEGACY_FILE_CHANGES = %i[creat unlink rmdir rename mkdir symlink link chmod chown lchown].freeze
    FILE_CHANGES = {x86_64: (COMMON_FILE_CHANGES + LEGACY_FILE_CHANGES).freeze, aarch64: COMMON_FILE_CHANGES}.freeze
    SUSPICIOUS = %i[memfd_create ptrace process_vm_writev init_module finit_module mount unshare setns bpf io_uring_setup perf_event_open keyctl].freeze
    DATAGRAMS = %i[sendto sendmsg sendmmsg].freeze

    module_function

    def file_changes(arch = RbConfig::CONFIG.fetch("host_cpu"))
      FILE_CHANGES.fetch(arch.to_sym)
    end
  end
end
