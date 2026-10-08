# frozen_string_literal: true

module Bonebed
  # Paths whose read attempts are kept even when the target file does not exist.
  module SensitivePath
    FLAGS = File::FNM_PATHNAME | File::FNM_DOTMATCH | File::FNM_EXTGLOB
    HOME = %w[
      .ssh/**/* .aws/**/* .gnupg/**/* .kube/**/* .azure/**/* .config/gcloud/**/* .config/gh/**/*
      .gem/credentials .netrc .git-credentials .docker/config.json .npmrc .pypirc .bundle/config
    ].freeze
    PROJECT = %w[.env .env.* config/master.key config/credentials.yml.enc config/credentials/**/*].freeze
    ABSOLUTE = %w[/etc/shadow /etc/gshadow /etc/sudoers /root/**/*].freeze

    module_function

    def match?(path, home:, cwd:)
      relative_match?(path, home, HOME) || relative_match?(path, cwd, PROJECT) ||
        ABSOLUTE.any? { |pattern| File.fnmatch?(pattern, path, FLAGS) }
    end

    def relative_match?(path, root, patterns)
      return false if root.nil? || !path.start_with?("#{root}/")

      relative = path.delete_prefix("#{root}/")
      patterns.any? { |pattern| File.fnmatch?(pattern, relative, FLAGS) }
    end
    private_class_method :relative_match?
  end
end
