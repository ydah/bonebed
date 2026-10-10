# frozen_string_literal: true

require_relative "../session"
require_relative "../bundler_runtime"
require_relative "../local_gem_repository"

module Bonebed
  module Phase
    module BundlerPlugin
      module_function

      def plugin_root(environment)
        File.join(environment.root, "bundler-observation", "plugin")
      end

      def call(environment, specification, packages:, **options)
        raise ArgumentError, "#{specification.name} does not declare a root plugins.rb" unless specification.files.include?("plugins.rb")

        BundlerRuntime.prepare(environment)
        root = File.dirname(plugin_root(environment))
        FileUtils.mkdir_p(root)
        gemfile = File.join(root, "Gemfile")
        File.write(gemfile, "# Isolated Bundler plugin observation; no application dependencies.\n")
        source = LocalGemRepository.build(File.join(environment.root, "plugin-repository"), packages)
        env = environment.env.merge(
          "BUNDLE_GEMFILE" => gemfile, "BUNDLE_APP_CONFIG" => root, "BUNDLE_USER_HOME" => root,
          "BUNDLE_USER_CONFIG" => File.join(root, "config"), "BUNDLE_USER_CACHE" => File.join(root, "cache"),
          "BUNDLE_USER_PLUGIN" => plugin_root(environment), "BUNDLE_PLUGINS" => "true",
          "BUNDLE_IGNORE_CONFIG" => "true", "BUNDLE_DISABLE_VERSION_CHECK" => "true",
          "BUNDLE_SILENCE_ROOT_WARNING" => "true", "BUNDLE_VERSION" => "system"
        )
        command = BundlerRuntime.command("plugin", "install", specification.name, "--version", specification.version.to_s, "--source", source)
        Session.new(command, env:, cwd: environment.project, unsetenv_others: true, **options).run
      end
    end
  end
end
