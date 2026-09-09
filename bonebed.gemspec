# frozen_string_literal: true

require_relative "lib/bonebed/version"

Gem::Specification.new do |spec|
  spec.name = "bonebed"
  spec.version = Bonebed::VERSION
  spec.authors = ["Yudai Takada"]
  spec.email = ["t.yudai92@gmail.com"]

  spec.summary = "Observe the runtime capabilities of Ruby gems"
  spec.description = "Profiles file, network, and process syscalls made while installing or requiring Ruby gems."
  spec.homepage = "https://github.com/ydah/bonebed"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"
  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir["lib/**/*", "exe/*", "README.md", "LICENSE.txt"]
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "seccomp-notify", "~> 0.3"
end
