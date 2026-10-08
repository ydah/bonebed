# frozen_string_literal: true

require "bonebed/landlock"

RSpec.describe Bonebed::Landlock do
  def in_restricted_child(**options)
    reader, writer = IO.pipe
    pid = fork do
      reader.close
      begin
        described_class.restrict!(**options)
        writer.write(JSON.generate(yield))
      rescue => error
        writer.write(JSON.generate("error" => "#{error.class}: #{error.message}"))
      ensure
        writer.close
      end
      exit! 0
    end
    writer.close
    result = JSON.parse(reader.read)
    Process.wait(pid)
    result
  ensure
    reader&.close
    writer&.close unless writer&.closed?
  end

  def require_landlock
    described_class.abi
  rescue described_class::Unavailable => error
    skip error.message
  end

  it "allows configured reads and writes while denying sibling files" do
    require_landlock
    Dir.mktmpdir do |root|
      allowed = File.join(root, "allowed")
      denied = File.join(root, "denied")
      writable = File.join(root, "write")
      File.write(allowed, "allowed")
      File.write(denied, "secret")
      Dir.mkdir(writable)
      result = in_restricted_child(read_paths: [allowed], write_paths: [writable]) do
        data = {"read" => File.read(allowed), "written" => File.write(File.join(writable, "created"), "ok")}
        [denied, allowed].each do |path|
          File.write(path, "overwrite")
          data[path] = "unexpected write"
        rescue Errno::EACCES
          data[path] = "denied"
        end
        begin
          File.read(denied)
          data["secret"] = "unexpected read"
        rescue Errno::EACCES
          data["secret"] = "denied"
        end
        data
      end
      expect(result).to eq("read" => "allowed", "written" => 2, allowed => "denied", denied => "denied", "secret" => "denied")
      expect(File.read(denied)).to eq("secret")
    end
  end

  it "supports write rules on individual files without granting access to siblings" do
    require_landlock
    Dir.mktmpdir do |root|
      file = File.join(root, "allowed")
      File.write(file, "before")
      result = in_restricted_child(read_paths: [], write_paths: [file]) do
        File.write(file, "after")
        {"read" => File.read(file)}
      end
      expect(result).to eq("read" => "after")
    end
  end

  it "validates paths and ports before changing process privileges" do
    expect(described_class).not_to receive(:enforce)
    expect { described_class.restrict!(read_paths: ["relative"], write_paths: []) }.to raise_error(ArgumentError, /absolute/)
    expect { described_class.restrict!(read_paths: ["/missing-bonebed-landlock-path"], write_paths: []) }.to raise_error(ArgumentError, /exist/)
    expect { described_class.restrict!(read_paths: [], write_paths: [], tcp_connect_ports: [65_536]) }.to raise_error(ArgumentError, /port/)
  end

  it "allows explicitly granted device access with file-only rights" do
    require_landlock
    result = in_restricted_child(read_paths: [], write_paths: ["/dev/null"]) do
      {"written" => File.write(File::NULL, "discard")}
    end
    expect(result).to eq("written" => 7)
  end

  it "keeps restrictions across exec" do
    require_landlock
    Dir.mktmpdir do |root|
      denied = File.join(root, "secret")
      File.write(denied, "secret")
      reader, writer = IO.pipe
      pid = fork do
        reader.close
        IO.for_fd(1, autoclose: false).reopen(writer)
        described_class.restrict!(read_paths: Bonebed::Enforcement.runtime_paths, write_paths: [])
        exec(RbConfig.ruby, "-e", 'begin; File.read(ARGV[0]); puts "escaped"; rescue Errno::EACCES; puts "denied"; end', denied, unsetenv_others: true)
      end
      writer.close
      output = reader.read
      _, status = Process.wait2(pid)
      expect(status.success?).to be(true)
      expect(output).to eq("denied\n")
    ensure
      reader&.close
      writer&.close unless writer&.closed?
    end
  end

  it "fails closed when the kernel cannot enforce a ruleset" do
    allow(described_class).to receive(:abi).and_raise(described_class::Unavailable, "Landlock unavailable")
    expect { described_class.restrict!(read_paths: [], write_paths: []) }.to raise_error(described_class::Unavailable)
  end

  it "rejects TCP allowlists on kernels without ABI 4 network controls" do
    allow(described_class).to receive(:abi).and_return(3)
    expect { described_class.restrict!(read_paths: [], write_paths: [], tcp_connect_ports: [443]) }.to raise_error(described_class::Unavailable, /ABI 4/)
  end

  it "allows one TCP destination port and denies another" do
    skip "Landlock ABI 4 is required" if require_landlock < 4
    allowed = TCPServer.new("127.0.0.1", 0)
    denied = TCPServer.new("127.0.0.1", 0)
    allowed_port = allowed.addr[1]
    denied_port = denied.addr[1]
    result = in_restricted_child(read_paths: [], write_paths: [], tcp_connect_ports: [allowed_port]) do
      TCPSocket.new("127.0.0.1", allowed_port).close
      begin
        TCPSocket.new("127.0.0.1", denied_port).close
        {"denied" => false}
      rescue Errno::EACCES
        {"denied" => true}
      end
    end
    expect(result).to eq("denied" => true)
  ensure
    allowed&.close
    denied&.close
  end
end
