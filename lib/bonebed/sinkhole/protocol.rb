# frozen_string_literal: true

module Bonebed
  module Sinkhole
    module Protocol
      LIMIT = 16_384

      module_function

      def dns(data)
        return unless data.bytesize.between?(17, 4096)
        id, flags, questions = data.unpack("n3")
        return unless (flags & 0xf800).zero? && questions == 1

        offset = 12
        labels = []
        loop do
          length = data.getbyte(offset)
          return unless length && length <= 63
          offset += 1
          break if length.zero?
          label = data.byteslice(offset, length)
          return unless label && label.bytesize == length && label.match?(/\A[a-zA-Z0-9_-]+\z/n)
          labels << label
          offset += length
          return if offset > 267
        end
        return if labels.empty? || offset + 4 > data.bytesize
        type, klass = data.byteslice(offset, 4).unpack("n2")
        return unless klass == 1
        offset += 4
        address = case type
        when 1 then [127, 0, 0, 1].pack("C4")
        when 28 then "\0" * 15 + "\1"
        end
        response = [id, 0x8080 | (flags & 0x100), 1, address ? 1 : 0, 0, 0].pack("n6") + data.byteslice(12, offset - 12)
        response += [0xc00c, type, 1, 0, address.bytesize].pack("nnnNn") + address if address
        [response, labels.join(".")]
      end

      def http(data)
        return if data.bytesize > LIMIT
        ending = data.index("\r\n\r\n")
        return unless ending
        lines = data.byteslice(0, ending).split("\r\n")
        request = /\A([A-Z]{1,32}) ([^\x00-\x20\x7f]{1,8192}) HTTP\/1\.[01]\z/n.match(lines.shift.to_s)
        return unless request
        hosts = lines.filter_map do |line|
          next unless line.match?(/\Ahost:/i)
          line.split(":", 2).last.strip
        end
        return unless hosts.size == 1 && text?(hosts.first, 1024)
        lengths = lines.filter_map { |line| line.split(":", 2).last.strip if line.match?(/\Acontent-length:/i) }
        return if lengths.size > 1 || (lengths.first && !lengths.first.match?(/\A[0-9]{1,12}\z/))
        body_length = lengths.first.to_i
        expected = ending + 4 + body_length.clamp(0, [4096 - ending - 4, 0].max)
        return if data.bytesize < expected
        {"protocol" => "http", "method" => request[1], "host" => hosts.first,
         "path" => request[2].force_encoding(Encoding::UTF_8).scrub,
         "sample" => data.byteslice(0, 4096).force_encoding(Encoding::UTF_8).scrub}
      end

      def tls(data)
        return if data.bytesize > LIMIT
        offset = 0
        handshake = +"".b
        while offset + 5 <= data.bytesize
          kind, version, length = data.byteslice(offset, 5).unpack("Cnn")
          return unless kind == 22 && (version >> 8) == 3 && length.positive? && offset + 5 + length <= data.bytesize
          handshake << data.byteslice(offset + 5, length)
          offset += 5 + length
          next if handshake.bytesize < 4
          return unless handshake.getbyte(0) == 1
          size = ("\0" + handshake.byteslice(1, 3)).unpack1("N")
          return if size > LIMIT - 4
          next if handshake.bytesize < size + 4
          return client_hello(handshake.byteslice(4, size))
        end
        nil
      end

      def client_hello(data)
        cursor = Cursor.new(data)
        cursor.read(34)
        cursor.read(cursor.byte)
        cursor.read(cursor.word)
        cursor.read(cursor.byte)
        extensions = Cursor.new(cursor.read(cursor.word))
        until extensions.empty?
          type = extensions.word
          value = extensions.read(extensions.word)
          next unless type.zero?
          list = Cursor.new(value)
          names = Cursor.new(list.read(list.word))
          until names.empty?
            name_type = names.byte
            name = names.read(names.word)
            return {"protocol" => "tls", "host" => name} if name_type.zero? && text?(name, 253)
          end
        end
        nil
      rescue ArgumentError
        nil
      end

      def text?(value, limit)
        value.bytesize.between?(1, limit) && value.match?(/\A[\x21-\x7e]+\z/n)
      end

      class Cursor
        def initialize(data)
          @data = data
          @offset = 0
        end

        def read(size)
          raise ArgumentError, "truncated protocol field" if @offset + size > @data.bytesize
          value = @data.byteslice(@offset, size)
          @offset += size
          value
        end

        def byte
          read(1).unpack1("C")
        end

        def word
          read(2).unpack1("n")
        end

        def empty?
          @offset == @data.bytesize
        end
      end
    end
  end
end
