# frozen_string_literal: true

require "ipaddr"

module Bonebed
  module Decoder
    module Connect
      MAX_LENGTH = 128

      module_function

      def call(bytes)
        raise ArgumentError, "sockaddr length must be between 2 and #{MAX_LENGTH}" unless (2..MAX_LENGTH).cover?(bytes.bytesize)

        case bytes.unpack1("S<")
        when 1 then {family: "unix", path: unix_path(bytes.byteslice(2..))}
        when 2 then internet_address("inet", bytes, 4)
        when 10 then internet_address("inet6", bytes, 8)
        else raise ArgumentError, "unsupported sockaddr family #{bytes.unpack1("S<")}"
        end
      end

      def internet_address(family, bytes, address_offset)
        length = family == "inet" ? 4 : 16
        minimum = family == "inet" ? 16 : 28
        raise ArgumentError, "short AF_#{family.upcase} sockaddr" if bytes.bytesize < minimum

        address = IPAddr.new_ntoh(bytes.byteslice(address_offset, length)).to_s
        scope = bytes.unpack1("@24L<") if family == "inet6"
        address = "#{address}%#{scope}" if scope&.positive?
        {family:, addr: address, port: bytes.unpack1("@2n")}
      end
      private_class_method :internet_address

      def unix_path(bytes)
        bytes.start_with?("\0") ? bytes.sub(/\0+\z/, "") : bytes.split("\0", 2).first
      end
      private_class_method :unix_path
    end
  end
end
