# frozen_string_literal: true

module OAuth
  module Header
    VERSION = 1.0

    attr_accessor :callback,
                  :consumer_key,
                  :consumer_secret,
                  :nonce,
                  :request_method,
                  :request_url,
                  :signature_method,
                  :timestamp,
                  :token,
                  :token_secret,
                  :pin

    def params
      hash = {
        oauth_nonce: nonce,
        oauth_consumer_key: consumer_key,
        oauth_signature_method: signature_method,
        oauth_timestamp: timestamp,
        oauth_callback: callback,
        oauth_version: VERSION
      }

      if request_token?
        hash[:oauth_token] = token
        hash[:oauth_verifier] = callback == 'oob' ? pin : callback
      end

      hash
    end

    def signed_params
      signature = base64_encode(OpenSSL::HMAC.digest('sha1', signature_key, signature_base))
      params.merge(oauth_signature: signature)
    end

    def normalized_params
      params.sort_by { |k, _v| k.to_s }.collect { |k, v| "#{k}=#{v}" }.join('&')
    end

    def normalized_signed_params
      signed_params
        .sort_by { |k, _v| k.to_s }
        .collect { |k, v| "#{k}=#{percent_encode(v)}" }
        .join('&')
    end

    def normalized_header_params
      signed_params
        .sort_by { |k, _v| k.to_s }
        .collect { |k, v| %{#{k}="#{percent_encode(v)}"} }
        .join(', ')
    end

    def authorization_header
      "OAuth #{normalized_header_params}"
    end

    def signature_key
      key = percent_encode(consumer_secret) + '&'
      key += percent_encode(token_secret) if request_token?
      key
    end

    def base_string_uri
      uri = URI(request_url)
      host = uri.host
      host += ":#{uri.port}" unless uri.port == 80 || uri.port == 443
      uri.scheme + '://' + host + uri.path
    end

    def signature_base
      [
        percent_encode(request_method.upcase.to_s),
        percent_encode(base_string_uri),
        percent_encode(normalized_params)
      ].join('&')
    end

    def request_token?
      !token.nil? && !token_secret.nil?
    end

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
