# frozen_string_literal: true

module Bonebed
  module CapabilityKeys
    module_function

    def call(manifest)
      counts(manifest).keys.sort
    end

    def counts(manifest)
      raise ArgumentError, "manifest must use schema version 1 or 2" unless manifest.is_a?(Hash) && [1, 2].include?(manifest.fetch("schema_version", 1))

      result = Hash.new(0)
      files = manifest.fetch("files", {})
      raise ArgumentError, "manifest files must be an object" unless files.is_a?(Hash)

      files.each do |mode, entries|
        next if %w[notable self_write].include?(mode)

        entries = entries.values.flat_map { |paths| list(paths) } if mode == "read" && entries.is_a?(Hash)
        list(entries).each do |entry|
          path = if entry.is_a?(Hash)
            entry.key?("from") ? "#{text(entry.fetch("from"))}:#{text(entry.fetch("to"))}" : text(entry.fetch("path"))
          else
            text(entry)
          end
          result["file:#{mode}:#{path}"] += count(entry)
        end
      end
      list(manifest.fetch("network", [])).each { |entry| result["network:#{endpoint(entry)}"] += count(entry) }
      list(manifest.fetch("listen", [])).each { |entry| result["listen:#{endpoint(entry)}"] += count(entry) }
      list(manifest.fetch("sockets", [])).each do |entry|
        family = text(entry.fetch("family"))
        type = entry.fetch("type")
        protocol = entry.fetch("protocol")
        raise ArgumentError, "invalid socket type or protocol" unless type.is_a?(Integer) && type >= 0 && protocol.is_a?(Integer) && protocol >= 0

        result["socket:#{family}:#{type}:#{protocol}"] += count(entry)
      end
      list(manifest["dns"] || []).each do |entry|
        name = entry.is_a?(Hash) ? entry.fetch("name") : entry
        result["network:dns:#{text(name)}"] += count(entry)
      end
      list(manifest.fetch("network_intent", [])).each do |entry|
        protocol = entry.fetch("protocol")
        raise ArgumentError, "invalid network intent protocol" unless %w[http tls].include?(protocol)

        result["network:#{protocol}:#{text(entry.fetch("host"))}"] += count(entry)
      end
      list(manifest.fetch("exec", [])).each do |entry|
        result["exec:#{text(entry.fetch("path"))}"] += count(entry)
        result["syscall:execveat"] += count(entry) if entry["syscall"] == "execveat"
      end
      {"processes" => "process:spawn", "threads" => "thread:spawn"}.each do |field, key|
        list(manifest.fetch(field, [])).each { |entry| result[key] += count(entry) }
      end
      list(manifest.fetch("suspicious", [])).each { |entry| result["syscall:#{text(entry.fetch("syscall"))}"] += count(entry) }
      list(manifest["canary_hits"] || []).each do |entry|
        result["canary:#{text(entry.fetch("source"))}:#{text(entry.fetch("seen_in"))}"] += count(entry)
      end
      list(manifest.fetch("anti_analysis", [])).each do |entry|
        value = entry.is_a?(Hash) ? entry.fetch("path") { entry.fetch("syscall") } : entry
        result["anti_analysis:#{text(value)}"] += count(entry)
      end
      list(manifest.fetch("denied", [])).each do |entry|
        key = text(entry.fetch("capability"))
        result[key] = [result[key], count(entry)].max
      end
      result.sort.to_h
    rescue KeyError, NoMethodError, TypeError => error
      raise ArgumentError, "invalid manifest capability: #{error.message}"
    end

    def endpoint(entry)
      family = text(entry.fetch("family"))
      return "unix:#{text(entry.fetch("path"))}" if family == "unix"
      return family unless %w[inet inet6].include?(family)

      address = text(entry.fetch("addr"))
      port = entry.fetch("port")
      raise ArgumentError, "invalid network port" unless port.is_a?(Integer) && (0..65535).cover?(port)

      "#{family}:#{(family == "inet6") ? "[#{address}]" : address}:#{port}"
    end

    def list(value)
      raise ArgumentError, "manifest capability must be an array" unless value.is_a?(Array)

      value
    end

    def text(value)
      raise ArgumentError, "manifest capability must be a nonempty string" unless value.is_a?(String) && !value.empty?

      value
    end

    def count(entry)
      value = entry.is_a?(Hash) ? entry.fetch("count", 1) : 1
      raise ArgumentError, "manifest count must be positive" unless value.is_a?(Integer) && value.positive?

      value
    end
  end
end
