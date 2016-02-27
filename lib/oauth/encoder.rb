module OAuth
  module Encoder
    def percent_encode(base_string)
      string = base_string.to_s
      encoding = string.encoding
      string.b.gsub(/([^ a-zA-Z0-9_.-]+)/) do |m|
        '%' + m.unpack('H2' * m.bytesize).join('%').upcase
      end.tr(' ', '+').force_encoding(encoding)
    end

    def base64_encode(string)
      [string].pack('m').chomp.delete "\n"
    end
  end
end
