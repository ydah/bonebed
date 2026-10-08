# frozen_string_literal: true

require "fileutils"
require "securerandom"

module Bonebed
  class Honeypot
    HOME_FILES = {
      ".ssh/id_ed25519" => ->(token) { "-----BEGIN OPENSSH PRIVATE KEY-----\n#{token}\n-----END OPENSSH PRIVATE KEY-----\n" },
      ".aws/credentials" => ->(token) { "[default]\naws_access_key_id = AKIA#{token[0, 16].upcase}\naws_secret_access_key = #{token}\n" },
      ".gem/credentials" => ->(token) { "---\n:rubygems_api_key: rubygems_#{token}\n" },
      ".netrc" => ->(token) { "machine example.invalid login bonebed password #{token}\n" },
      ".config/gh/hosts.yml" => ->(token) { "github.com:\n    oauth_token: gho_#{token}\n" },
      ".docker/config.json" => ->(token) { %({"auths":{"example.invalid":{"auth":"#{token}"}}}\n) },
      ".kube/config" => ->(token) { "apiVersion: v1\nusers:\n- name: bonebed\n  user:\n    token: #{token}\n" }
    }.freeze
    PROJECT_FILES = {
      ".env" => ->(token) { "SECRET_KEY_BASE=#{token}\n" },
      "config/master.key" => ->(token) { token }
    }.freeze
    ENV_TOKENS = %w[AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY GITHUB_TOKEN GEM_HOST_API_KEY].freeze

    attr_reader :env

    def initialize(home:, project:)
      @tokens = {}
      write_credentials(home, HOME_FILES) if home
      if project
        write_credentials(project, PROJECT_FILES)
        write(project, "Gemfile", "source \"https://rubygems.org\"\n")
        write(project, ".git/config", "[core]\n\trepositoryformatversion = 0\n")
      end
      @env = ENV_TOKENS.to_h do |name|
        token = SecureRandom.hex(20)
        token = "AKIA#{token[0, 16].upcase}" if name == "AWS_ACCESS_KEY_ID"
        @tokens[token] = "env:#{name}"
        [name, token]
      end
      @pattern = Regexp.union(@tokens.keys.sort_by { |token| -token.length })
    end

    def redact(manifest)
      hits = []
      result = manifest.to_h { |key, value| [key, redact_value(value, key.to_s, hits)] }
      result["canary_hits"] = (result.fetch("canary_hits", []) + hits).uniq
      result
    end

    private

    def write_credentials(root, templates)
      templates.each do |source, template|
        token = SecureRandom.hex((source == "config/master.key") ? 16 : 20)
        @tokens[token] = source
        @tokens["AKIA#{token[0, 16].upcase}"] = source if source == ".aws/credentials"
        @tokens["rubygems_#{token}"] = source if source == ".gem/credentials"
        @tokens["gho_#{token}"] = source if source == ".config/gh/hosts.yml"
        write(root, source, template.call(token))
      end
    end

    def write(root, relative, content)
      path = File.join(root, relative)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, content, mode: "w", perm: 0o600)
    end

    def redact_value(value, seen_in, hits)
      case value
      when String
        value.gsub(@pattern) do |token|
          source = @tokens.fetch(token)
          hits << {"source" => source, "seen_in" => seen_in}
          "[CANARY:#{source}]"
        end
      when Array
        value.map { |item| redact_value(item, seen_in, hits) }
      when Hash
        value.to_h { |key, item| [redact_value(key, seen_in, hits), redact_value(item, seen_in, hits)] }
      else
        value
      end
    end
  end
end
