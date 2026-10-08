# frozen_string_literal: true

require_relative "../session"

module Bonebed
  module Phase
    module Plugin
      module_function

      def call(environment, **options)
        Session.new([RbConfig.ruby, "-S", "gem", "env"], env: environment.env, cwd: environment.project,
          unsetenv_others: true, **options).run
      end
    end
  end
end
