# frozen_string_literal: true

# Standard Libraries
require 'net/http'
require 'openssl'
require 'uri'

# RubyGems
require 'bundler'
Bundler.require

class OAuth
  VERSION = '1.0'

  attr_accessor :callback,
                :consumer_key,
                :consumer_secret,
                :nonce,
                :request_method,
                :request_url,
                :signature_method,
                :timestamp,
                :token,
                :token_secret

  def initialize(opts = {})
    consumer_key = nil
    consumer_secret = nil
    yield self if block_given?

    self.consumer_key    ||= opts[:consumer_key]
    self.consumer_secret ||= opts[:consumer_secret]

    self.signature_method ||= 'HMAC-SHA1'
    self.timestamp        ||= Time.now.to_i.to_s
    self.nonce            ||= OpenSSL::Random.random_bytes(16).unpack('H*')[0]
    self.callback         ||= 'oob'
  end

  def params
    {
      oauth_nonce: nonce,
      oauth_consumer_key: consumer_key,
      oauth_signature_method: signature_method,
      oauth_timestamp: timestamp,
      oauth_callback: callback,
      oauth_version: VERSION
    }
  end

  def signed_params
    signature =
      [OpenSSL::HMAC.digest('sha1', signature_key, signature_base)].pack('m').chomp.gsub(/\n/, '')

    params.merge({oauth_signature: signature})
  end

  def normalized_header_params
    signed_params.sort_by { |k, _v| k.to_s }.collect { |k, v| %(#{k}="#{escape v}") }.join(', ')
  end

  def normalized_params
    params.sort_by { |k, _v| k.to_s }.collect { |k, v| "#{k}=#{v}" }.join('&')
  end

  def authorization_header
    "OAurh #{normalized_header_params}"
  end

  def base_string_uri
    uri = URI.parse(request_url)
    host = uri.host
    host += ":#{uri.port}" unless uri.port == 80 || uri.port == 443
    uri.scheme + '://' + host + uri.path
  end

  def signature_base
    escape "#{request_method.upcase}&#{base_string_uri}&#{normalized_params}"
  end

  def signature_key
    key = escape(consumer_secret) + '&'
    key += escape(token_secret) if has_token?
    key
  end

  def has_token?
    !token.nil? && !token_secret.nil?
  end

  def escape(string)
    encoding = string.encoding
    string.b.gsub(/([^ a-zA-Z0-9_.-]+)/) do |m|
      '%' + m.unpack('H2' * m.bytesize).join('%').upcase
    end.tr(' ', '+').force_encoding(encoding)
  end

  def get_request_token(method, url)
    self.request_url = url
    self.request_method = method

    uri = URI.parse(request_url)
    uri.query = normalized_params if method.to_s.upcase == 'GET'

    https = Net::HTTP.new(uri.host, uri.port)
    https.use_ssl = true

    req = Net::HTTP::const_get(request_method.capitalize.to_sym).new(uri.path)
    req['Authorization'] = authorization_header if method.to_s.upcase == 'POST'

    res = https.request(req)
    res.body
  end
end
