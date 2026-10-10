# frozen_string_literal: true

require "bundler/plugin/api"
require "bonebed-bundler-dependency"

raise "fixture plugin failure" if ENV["BONEBED_PLUGIN_RAISE"]

File.write(File.join(ENV.fetch("HOME"), ".bundler-plugin-probe"), Bundler::VERSION)
Bundler::Plugin::API.command("bonebed-fixture-noop", Class.new do
  def exec(*arguments)
  end
end)
