# frozen_string_literal: true

require "yaml"

module Bonebed
  module Enforcement
    module_function

    def load(path, environment)
      config = YAML.safe_load_file(path, permitted_classes: [], aliases: false)
      keys = %w[read_paths write_paths tcp_connect_ports tcp_bind_ports]
      raise ArgumentError, "invalid enforcement policy" unless config.is_a?(Hash) && (config.keys - keys).empty?

      runtime = %w[/usr /lib /lib64 /etc/ld.so.cache /etc/hosts /etc/resolv.conf /etc/nsswitch.conf /dev/urandom /dev/random]
      result = {read_paths: runtime.select { |entry| File.exist?(entry) }, write_paths: [environment.root, "/dev/null"],
                tcp_connect_ports: [], tcp_bind_ports: []}
      config.each do |key, values|
        raise ArgumentError, "#{key} must be an array" unless values.is_a?(Array)

        if key.end_with?("paths")
          paths = values.map do |value|
            raise ArgumentError, "path must be a string" unless value.is_a?(String)

            value.sub(/\A\$HOME(?=\/|\z)/, environment.home).sub(/\A\$PWD(?=\/|\z)/, environment.project)
              .sub(/\A\$GEM_HOME(?=\/|\z)/, environment.gem_home).sub(/\A\$TMPDIR(?=\/|\z)/, environment.tmpdir)
          end
          result[key.to_sym] |= paths
        else
          raise ArgumentError, "invalid TCP port" unless values.all? { |value| value.is_a?(Integer) && (0..65_535).cover?(value) }

          result[key.to_sym] = values
        end
      end
      result
    rescue Psych::Exception => error
      raise ArgumentError, "invalid enforcement YAML: #{error.message}"
    end

    def generate(manifests)
      reads = manifests.flat_map do |manifest|
        value = manifest.dig("files", "read") || []
        value.is_a?(Hash) ? value.values.flatten : value
      end
      writes = manifests.flat_map { |manifest| manifest.dig("files", "write") || [] }
      {"read_paths" => reads.uniq.sort, "write_paths" => writes.uniq.sort,
       "tcp_connect_ports" => manifests.flat_map { |manifest| Array(manifest["network"]).filter_map { |event| event["port"] } }.uniq.sort,
       "tcp_bind_ports" => manifests.flat_map { |manifest| Array(manifest["listen"]).filter_map { |event| event["port"] } }.uniq.sort}
    end
  end
end
