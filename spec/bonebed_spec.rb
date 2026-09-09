# frozen_string_literal: true

RSpec.describe Bonebed do
  it "has a version number" do
    expect(Bonebed::VERSION).not_to be nil
  end

  it "reports platform support without crashing" do
    output = StringIO.new
    doctor = Bonebed::Doctor.new(output:)

    expect { doctor.run }.not_to raise_error
    expect(output.string).to include("kernel", "arch", "SECCOMP_RET_USER_NOTIF")
  end
end
