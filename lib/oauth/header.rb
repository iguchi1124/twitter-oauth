# frozen_string_literal: true

module OAuth
  module Header
    VERSION = 1.0

    attr_accessor :access_token,
                  :access_token_secret,
                  :callback,
                  :consumer_key,
                  :consumer_secret,
                  :request_token,
                  :request_token_secret

    def params
      params = {
        oauth_nonce: @nonce ||= nonce,
        oauth_consumer_key: consumer_key,
        oauth_signature_method: 'HMAC-SHA1',
        oauth_timestamp: @timestamp ||= timestamp,
        oauth_version: VERSION
      }

      if has_access_token?
        params[:oauth_token] = access_token
      elsif has_request_token?
        params[:oauth_token] = request_token
        params[:oauth_verifier] = callback == 'oob' ? pin : callback
      else
        params[:oauth_callback] = callback
      end

      params
    end

    def nonce
      OpenSSL::Random.random_bytes(16).unpack('H*')[0]
    end

    def timestamp
      Time.now.to_i.to_s
    end

    def reset_onetime_params!
      @nonce = nil
      @timestamp = nil
    end

    def signed_params
      signature = base64_encode(OpenSSL::HMAC.digest('sha1', signature_key, signature_base))
      params.merge(oauth_signature: signature)
    end

    def normalized_params
      params.merge(@options).sort_by { |k, _v| k.to_s }.collect { |k, v| "#{k}=#{v}" }.join('&')
    end

    def normalized_signed_params
      signed_params
        .sort_by { |k, _v| k.to_s }
        .collect { |k, v| "#{k}=#{percent_encode(v)}" }
        .join('&')
    end

    def authorization_header
      normalized_header_params =
        signed_params.sort_by { |k, _v| k.to_s }
                     .collect { |k, v| %{#{k}="#{percent_encode(v)}"} }
                     .join(', ')

      "OAuth #{normalized_header_params}"
    end

    def signature_key
      key = percent_encode(consumer_secret) + '&'
      if has_access_token?
        key +=  percent_encode(access_token_secret)
      elsif has_request_token?
        key +=  percent_encode(request_token_secret)
      end

      key
    end

    def base_string_uri
      host = @uri.host.downcase
      host += ":#{@uri.port}" unless @uri.port == 80 || @uri.port == 443
      @uri.scheme + '://' + host + @uri.path.downcase
    end

    def signature_base
      [
        percent_encode(@method),
        percent_encode(base_string_uri),
        percent_encode(normalized_params)
      ].join('&')
    end

    def has_request_token?
      !(@request_token.nil? || @request_token_secret.nil?)
    end

    def has_access_token?
      !(@access_token.nil? || @access_token_secret.nil?)
    end

    def percent_encode(str)
      str = str.to_s
      encoding = str.encoding
      str.b.gsub(/([^ a-zA-Z0-9_.-]+)/) do |m|
        '%' + m.unpack('H2' * m.bytesize).join('%').upcase
      end.tr(' ', '+').force_encoding(encoding)
    end

    def base64_encode(str)
      [str].pack('m').chomp.delete "\n"
    end
  end
end
