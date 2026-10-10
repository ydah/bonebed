# frozen_string_literal: true

require "json"
require "rbconfig"
require "securerandom"
require "openssl"
require_relative "collector"
require_relative "isolation"

module Bonebed
  module Sinkhole
    class Unavailable < ObserverError; end
    MAX_INPUT = 1_048_576
    MAX_OUTPUT = 33_554_432
    OPTIONS = %i[unsetenv_others output_limit argv_limit writes_only enforcement resource_limits trace deny].freeze

    module_function

    def run(command, env: {}, cwd: Dir.pwd, timeout: 30, collector: Collector.new, quiet_target: false, target_stdout: $stdout, redactor: nil, **options)
      validate_options!(command, env, cwd, timeout, options)
      prefix = namespace_prefix
      transport_key = SecureRandom.hex(32)
      inherited = options.fetch(:unsetenv_others, true) ? {} : ENV.to_h
      configuration = {"command" => command, "env" => inherited.merge(env), "cwd" => File.expand_path(cwd), "timeout" => timeout,
                       "namespace" => File.readlink("/proc/self/ns/net"), "transport_key" => transport_key,
                       "options" => options.except(:trace).merge(unsetenv_others: true)}
      input = JSON.generate(configuration)
      raise ArgumentError, "sinkhole configuration is too large" if input.bytesize > MAX_INPUT
      result = invoke(prefix, input, timeout, transport_key)
      raise Unavailable, result.fetch("error") if result.key?("error")
      begin
        collector.import_state!(result.fetch("collector"))
      rescue ArgumentError => error
        raise Unavailable, "invalid sinkhole result: #{error.message}"
      end
      unless quiet_target
        output = result.fetch("collector").slice("stdout", "stderr")
        output = redactor.redact(output) if redactor
        target_stdout.write(output.fetch("stdout"))
        $stderr.write(output.fetch("stderr"))
      end
      collector
    rescue JSON::ParserError, KeyError, IOError, SystemCallError => error
      raise Unavailable, "sinkhole failed: #{error.message}"
    end

    def validate_options!(command, env, cwd, timeout, options)
      valid = command.is_a?(Array) && !command.empty? && command.all? { |value| value.is_a?(String) && !value.include?("\0") } && !command.first.empty?
      raise ArgumentError, "sinkhole command must be an argv array" unless valid
      valid_env = env.is_a?(Hash) && env.all? { |key, value| key.is_a?(String) && (value.nil? || value.is_a?(String)) }
      raise ArgumentError, "invalid sinkhole environment" unless valid_env
      raise ArgumentError, "invalid sinkhole cwd" unless cwd.is_a?(String) && File.directory?(cwd)
      raise ArgumentError, "invalid sinkhole timeout" unless timeout.is_a?(Numeric) && timeout.positive? && timeout.finite?
      raise ArgumentError, "unsupported sinkhole option" unless (options.keys - OPTIONS).empty?
      raise ArgumentError, "trace is not yet supported in sinkhole mode" if options[:trace]
    end

    def namespace_prefix
      raise Unavailable, "sinkhole requires Linux network namespaces" unless RUBY_PLATFORM.include?("linux")
      executable = %w[/usr/bin/unshare /bin/unshare].find { |path| File.executable?(path) }
      raise Unavailable, "sinkhole requires util-linux unshare" unless executable
      [executable, "--user", "--map-root-user", "--net", "--fork", "--kill-child=TERM", "--"]
    end

    def invoke(prefix, input, timeout, transport_key)
      request_read, request_write = IO.pipe
      result_read, result_write = IO.pipe
      error_read, error_write = IO.pipe
      environment = {"PATH" => ENV.fetch("PATH", "/usr/bin:/bin"), "GEM_PATH" => Gem.path.join(File::PATH_SEPARATOR), "LANG" => "C.UTF-8"}
      worker = File.expand_path("sinkhole_worker.rb", __dir__)
      pid = Process.spawn(environment, *prefix, RbConfig.ruby, "-I", File.expand_path("..", __dir__), worker,
        :in => request_read, :out => File::NULL, :err => error_write, 3 => result_write, :pgroup => true, :unsetenv_others => true)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout + 10
      [request_read, result_write, error_write].each(&:close)
      offset = 0
      while offset < input.bytesize
        remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        raise Unavailable, "sinkhole worker timed out" unless remaining.positive?
        next unless IO.select(nil, [request_write], nil, [remaining, 0.1].min)
        written = request_write.write_nonblock(input.byteslice(offset, 16_384), exception: false)
        offset += written unless written == :wait_writable
      end
      request_write.close
      result = +"".b
      diagnostics = +"".b
      readers = [result_read, error_read]
      until readers.empty?
        remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        raise Unavailable, "sinkhole worker timed out" unless remaining.positive?
        ready = IO.select(readers, nil, nil, [remaining, 0.1].min)&.first || []
        ready.each do |reader|
          bytes = reader.read_nonblock(16_384, exception: false)
          if bytes.nil?
            readers.delete(reader)
          elsif bytes != :wait_readable
            if reader == result_read
              result << bytes
              raise Unavailable, "sinkhole result exceeds #{MAX_OUTPUT} bytes" if result.bytesize > MAX_OUTPUT
            elsif diagnostics.bytesize < 65_536
              diagnostics << bytes.byteslice(0, 65_536 - diagnostics.bytesize)
            end
          end
        end
      end
      until (waited = Process.waitpid2(pid, Process::WNOHANG))
        raise Unavailable, "sinkhole worker timed out" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        sleep 0.02
      end
      _, status = waited
      pid = nil
      raise Unavailable, "sinkhole worker failed: #{diagnostics.force_encoding(Encoding::UTF_8).scrub.strip}" unless status.success? && !result.empty?
      parsed = decode_response(result, transport_key)
      valid = parsed.is_a?(Hash) && ((parsed.keys == ["collector"] && parsed["collector"].is_a?(Hash)) || (parsed.keys == ["error"] && parsed["error"].is_a?(String)))
      raise Unavailable, "invalid sinkhole worker response" unless valid
      parsed
    ensure
      stop_worker(pid) if pid
      [request_read, request_write, result_read, result_write, error_read, error_write].compact.each { |io| io.close unless io.closed? }
    end

    def encode_response(data, key)
      payload = JSON.generate(data)
      JSON.generate("payload" => payload, "mac" => OpenSSL::HMAC.hexdigest("SHA256", key, payload))
    end

    def decode_response(result, key)
      envelope = JSON.parse(result, max_nesting: 4)
      valid = envelope.is_a?(Hash) && envelope.keys.sort == %w[mac payload] && envelope["payload"].is_a?(String) &&
        envelope["mac"].is_a?(String) && envelope["mac"].match?(/\A[0-9a-f]{64}\z/)
      raise Unavailable, "invalid sinkhole response envelope" unless valid
      expected = OpenSSL::HMAC.hexdigest("SHA256", key, envelope.fetch("payload"))
      raise Unavailable, "sinkhole response authentication failed" unless OpenSSL.fixed_length_secure_compare(expected, envelope.fetch("mac"))
      JSON.parse(envelope.fetch("payload"), max_nesting: 32)
    end

    def stop_worker(pid)
      tracked = Isolation.descendants(pid)
      Process.kill("TERM", -pid)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
      loop do
        return if Process.waitpid(pid, Process::WNOHANG)
        break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        sleep 0.02
      end
      Process.kill("KILL", -pid)
      Process.waitpid(pid)
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    ensure
      Isolation.cleanup(tracked || {})
    end
  end
end
