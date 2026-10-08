# frozen_string_literal: true

require "shellwords"

module Bonebed
  class StaticAnalysis
    NOTES = ["Matching observed capabilities does not prove that a source line executed.",
      "Unobserved calls may depend on inputs or paths not exercised; these signals do not establish malicious behavior."].freeze

    def self.prism_available?
      require "prism"
      true
    rescue LoadError
      false
    end

    def self.call(path, manifest: nil)
      new(path, manifest:).call
    end

    def initialize(path, manifest: nil)
      @path = File.expand_path(path)
      @manifest = manifest
      raise ArgumentError, "source path does not exist: #{path}" unless File.file?(@path) || File.directory?(@path)
    end

    def call
      result = {"available" => self.class.prism_available?, "signals" => [], "errors" => [], "notes" => NOTES}
      return result.merge("reason" => "Prism is unavailable; install prism or use Ruby 3.3 or newer") unless result["available"]

      directory = File.directory?(@path)
      files = directory ? Dir.glob(File.join(@path, "**", "*.rb")).sort.reject { |file| File.symlink?(file) || !File.realpath(file).start_with?(File.realpath(@path) + File::SEPARATOR) } : [@path]
      files.each do |file|
        label = directory ? file.delete_prefix(@path + File::SEPARATOR) : File.basename(file)
        parsed = Prism.parse(File.binread(file))
        result["errors"].concat(parsed.errors.map { |error| {"file" => label, "line" => error.location.start_line, "message" => error.message} })
        next unless parsed.errors.empty?

        nodes = [parsed.value]
        until nodes.empty?
          node = nodes.pop
          signal = signal_for(node)
          if signal
            signal["file"] = label
            signal["line"] = node.location.start_line
            signal["observed"] = observed(signal)
            result["signals"] << signal
          end
          nodes.concat(node.compact_child_nodes.reverse)
        end
      end
      result
    end

    private

    def signal_for(node)
      if node.is_a?(Prism::XStringNode) || node.is_a?(Prism::InterpolatedXStringNode)
        return {"kind" => "exec", "call" => "backticks", "literal" => node.is_a?(Prism::XStringNode) ? node.unescaped : nil}
      end
      return unless node.is_a?(Prism::CallNode)

      receiver = node.receiver
      constant = constant_name(receiver)
      implicit = receiver.nil? || receiver.is_a?(Prism::SelfNode)
      name = node.name.to_s
      kind = if %w[system exec spawn].include?(name) && (implicit || constant == "Kernel" || (constant == "Process" && %w[exec spawn].include?(name)))
        "exec"
      elsif name == "eval" && (implicit || constant == "Kernel")
        "eval"
      elsif %w[Net::HTTP Socket TCPSocket UDPSocket TCPServer UNIXSocket UNIXServer].include?(constant)
        "network"
      end
      return unless kind

      argument = node.arguments&.arguments&.first
      {"kind" => kind, "call" => constant ? "#{constant}.#{name}" : name,
       "literal" => argument.is_a?(Prism::StringNode) ? argument.unescaped : nil}
    end

    def constant_name(node)
      node.full_name.delete_prefix("::") if node.is_a?(Prism::ConstantReadNode) || node.is_a?(Prism::ConstantPathNode)
    rescue Prism::ConstantPathNode::DynamicPartsInConstantPathError
      nil
    end

    def observed(signal)
      return unless @manifest

      case signal["kind"]
      when "exec"
        literal = signal["literal"]
        return unless literal

        command = Shellwords.split(literal).first
        return unless command

        Array(@manifest["exec"]).any? do |entry|
          path = entry.is_a?(Hash) ? entry["path"] : entry
          path.is_a?(String) && (path == command || (!command.include?("/") && File.basename(path) == command))
        end
      when "network"
        %w[network dns sockets listen].any? { |key| !Array(@manifest[key]).empty? }
      end
    rescue ArgumentError
      nil
    end
  end
end
