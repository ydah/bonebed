# frozen_string_literal: true

module Bonebed
  module Decoder
    module DNS
      MAX_QUESTIONS = 4

      module_function

      def questions(payload)
        return [] if payload.bytesize < 12

        flags, count = payload.unpack("@2nn")
        return [] unless (flags & 0x8000).zero?

        offset = 12
        Array.new([count, MAX_QUESTIONS].min) do
          start = offset
          labels = []
          loop do
            length = payload.getbyte(offset)
            return [] unless length

            offset += 1
            return [] if offset - start > 255
            break if length.zero?
            # ponytail: compressed question names are rejected; support pointers if real resolvers require them.
            return [] if length > 63 || offset + length > payload.bytesize

            labels << payload.byteslice(offset, length).b.gsub(/[^\x21-\x7e]|[.\\]/n) { |byte| "\\#{byte.ord.to_s.rjust(3, "0")}" }
            offset += length
          end
          return [] if offset + 4 > payload.bytesize

          offset += 4
          labels.join(".").force_encoding(Encoding::UTF_8)
        end
      end
    end
  end
end
