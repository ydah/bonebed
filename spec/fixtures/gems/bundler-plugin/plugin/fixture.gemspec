# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = "bonebed-bundler-probe"
  spec.version = "1.0.0"
  spec.summary = "Bundler plugin registration observation fixture"
  spec.authors = ["Bonebed"]
  spec.license = "MIT"
  spec.homepage = "https://example.invalid"
  spec.required_ruby_version = ">= 3.2"
  spec.files = ["plugins.rb", "lib/bonebed-bundler-probe.rb"]
  spec.add_dependency "bonebed-bundler-dependency", "= 1.0.0"
end
