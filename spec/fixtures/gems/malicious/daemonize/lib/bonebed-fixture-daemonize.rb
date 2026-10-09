# frozen_string_literal: true

raise "run only in the disposable fixture harness" unless ENV["BONEBED_ADVERSARIAL_FIXTURE"] == "1"

reader, writer = IO.pipe
child = fork do
  reader.close
  Process.setsid
  fork do
    writer.puts(Process.pid)
    writer.close
    [$stdin, $stdout, $stderr].each(&:close)
    sleep 30
    exit! 0
  end
  writer.close
  exit! 0
end
writer.close
puts reader.gets
reader.close
Process.wait(child)
