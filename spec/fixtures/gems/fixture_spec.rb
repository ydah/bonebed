# frozen_string_literal: true

def fixture_spec(root, name, extensions: [])
  Gem::Specification.new do |spec|
    spec.name = name
    spec.version = "0.1.0"
    spec.summary = "Bonebed integration fixture"
    spec.authors = ["Bonebed"]
    spec.files = Dir.chdir(root) { Dir["lib/**/*", "ext/**/*"] }
    spec.require_paths = ["lib"]
    spec.extensions = extensions
  end
end
