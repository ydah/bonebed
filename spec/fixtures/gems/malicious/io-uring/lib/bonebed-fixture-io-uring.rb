# frozen_string_literal: true

raise "run only in the disposable fixture harness" unless ENV["BONEBED_ADVERSARIAL_FIXTURE"] == "1"

require "fiddle"
call = Fiddle::Function.new(Fiddle.dlopen(nil)["syscall"], [Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP], Fiddle::TYPE_LONG)
parameters = Fiddle::Pointer.malloc(256)
parameters[0, 256] = "\0" * 256
result = call.call(Integer(ENV.fetch("BONEBED_SYSCALL_IO_URING_SETUP")), 1, parameters)
raise "expected ENOSYS, got #{result}/#{Fiddle.last_error}" unless result == -1 && Fiddle.last_error == Errno::ENOSYS::Errno
puts "ENOSYS"
