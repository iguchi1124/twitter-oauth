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
    yield self if block_given?

    self.consumer_key    ||= opts['consumer_key']
    self.consumer_secret ||= opts['consumer_secret']

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
      .collect { |k, v| %(#{k}="#{percent_encode(v)}") }
      .join(', ')
  end

  def authorization_header
    "OAuth #{normalized_header_params}"
  end

  def signature_key
    key = percent_encode(consumer_secret) + '&'
    key += percent_encode(token_secret) if !token.nil? && !token_secret.nil?
    key
  end

  def base_string_uri
    uri = URI.parse(request_url)
    host = uri.host
    host += ":#{uri.port}" unless uri.port == 80 || uri.port == 443
    uri.scheme + '://' + host + uri.path
  end

  def signature_base
    [
      "#{percent_encode(request_method.upcase)}",
      "#{percent_encode(base_string_uri)}",
      "#{percent_encode(normalized_params)}"
    ].join('&')
  end

  def percent_encode(string)
    encoding = string.encoding
    string.b.gsub(/([^ a-zA-Z0-9_.-]+)/) do |m|
      '%' + m.unpack('H2' * m.bytesize).join('%').upcase
    end.tr(' ', '+').force_encoding(encoding)
  end

  def base64_encode(string)
    [string].pack('m').chomp.gsub(/\n/, '')
  end

  def get_request_token(method, url)
    self.request_url = url
    self.request_method = method.to_s

    uri = URI(request_url)
    uri.query = normalized_signed_params if request_method.upcase == 'GET'

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true if uri.port == 443

    req = Net::HTTP.const_get(request_method.capitalize.to_sym).new(uri)
    req['Authorization'] = authorization_header if request_method.upcase == 'POST'

    res = http.request(req)
    res.body
  end
end

require 'yaml'
client = OAuth.new(YAML.load_file('secrets.yml'))

puts client.get_request_token(:post, 'https://api.twitter.com/oauth/request_token')
