# frozen_string_literal: true

raise "run only in the disposable fixture harness" unless ENV["BONEBED_ADVERSARIAL_FIXTURE"] == "1"

require "fiddle"
call = Fiddle::Function.new(Fiddle.dlopen(nil)["syscall"], Array.new(7, Fiddle::TYPE_LONG), Fiddle::TYPE_LONG)
name = Fiddle::Pointer["bonebed-fixture\0"]
fd = call.call(Integer(ENV.fetch("BONEBED_SYSCALL_MEMFD_CREATE")), name.to_i, 0, 0, 0, 0, 0)
raise "memfd_create failed" if fd.negative?
IO.for_fd(fd, autoclose: false).write(File.binread("/bin/true"))
argument = Fiddle::Pointer["true\0"]
arguments = Fiddle::Pointer[[argument.to_i, 0].pack("J*")]
environment = Fiddle::Pointer[[0].pack("J")]
empty = Fiddle::Pointer["\0"]
call.call(Integer(ENV.fetch("BONEBED_SYSCALL_EXECVEAT")), fd, empty.to_i, arguments.to_i, environment.to_i, 0x1000, 0)
raise "execveat failed: #{Fiddle.last_error}"
