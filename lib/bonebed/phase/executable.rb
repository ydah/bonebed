# frozen_string_literal: true

require "rbconfig"
require_relative "../session"

module Bonebed
  module Phase
    module Executable
      module_function

      def select(specification, executable = nil)
        declared = specification.executables
        raise ArgumentError, "#{specification.name} has no executable" if declared.empty?
        raise ArgumentError, "multiple executables; select one with --executable" if executable.nil? && declared.size > 1

        executable ||= declared.first
        raise ArgumentError, "executable is not declared by #{specification.name}: #{executable}" unless declared.include?(executable)
        raise ArgumentError, "invalid executable name" unless executable.is_a?(String) && executable.match?(/\A[0-9A-Za-z][0-9A-Za-z._-]*\z/)

        executable
      end

      def command(environment, executable, arguments)
        [RbConfig.ruby, File.join(environment.gem_home, "bin", executable), *arguments]
      end

      def call(environment, specification, executable: nil, arguments: [], **options)
        executable = select(specification, executable)
        Session.new(command(environment, executable, arguments), env: environment.env, cwd: environment.project,
          unsetenv_others: true, **options).run
      end
    end
  end
end
