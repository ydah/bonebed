# frozen_string_literal: true

require "fileutils"
require "tmpdir"

RSpec.describe Bonebed::Dig do
  it "separates installed gem versions from platforms and lists dependencies" do
    Dir.mktmpdir do |gem_home|
      specifications = File.join(gem_home, "specifications")
      FileUtils.mkdir_p(specifications)
      File.write(File.join(specifications, "nokogiri-1.19.4-aarch64-linux-gnu.gemspec"),
        "# -*- encoding: utf-8 -*-\n# stub: nokogiri 1.19.4 aarch64-linux-gnu lib\n\n")
      File.write(File.join(specifications, "racc-1.8.1.gemspec"),
        "# -*- encoding: utf-8 -*-\n# stub: racc 1.8.1 ruby lib\n\n")

      expect(described_class.new.send(:installed_gems, gem_home)).to eq([
        {"name" => "nokogiri", "version" => "1.19.4", "platform" => "aarch64-linux-gnu"},
        {"name" => "racc", "version" => "1.8.1", "platform" => "ruby"}
      ])
    end
  end
end
