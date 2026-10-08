# frozen_string_literal: true

require "rbconfig"
require_relative "../session"

module Bonebed
  module Phase
    module Install
      module_function

      def call(environment, packages, **options)
        command = [RbConfig.ruby, "-S", "gem", "install", "--local", "--ignore-dependencies",
          "--no-document", "--install-dir", environment.gem_home, *packages]
        Session.new(command, env: environment.env, cwd: environment.project, unsetenv_others: true, **options).run
      end
    end
  end
end
