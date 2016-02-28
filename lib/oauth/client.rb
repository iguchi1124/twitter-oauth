# frozen_string_literal: true

# Standard Libraries
require 'net/http'
require 'openssl'
require 'uri'

# RubyGems
require 'bundler'
Bundler.require

module OAuth
  class Client
    include OAuth::Header

    def initialize(opts = {})
      yield self if block_given?

      self.consumer_key    ||= opts['consumer_key']
      self.consumer_secret ||= opts['consumer_secret']

      self.signature_method ||= 'HMAC-SHA1'
      self.timestamp        ||= Time.now.to_i.to_s
      self.nonce            ||= OpenSSL::Random.random_bytes(16).unpack('H*')[0]
      self.callback         ||= opts['callback'] || 'oob'
    end

    def get(url)
      self.request_url = url
      self.request_method = :get

      uri = URI(request_url)
      uri.query = normalized_signed_params

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true if uri.port == 443

      req = Net::HTTP::Get.new(uri)

      res = http.request(req)
      res.body
    end

    def post(url)
      self.request_url = url
      self.request_method = :post

      uri = URI(request_url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true if uri.port == 443

      req = Net::HTTP::Post.new(uri)
      req['Authorization'] = authorization_header

      res = http.request(req)
      res.body
    end

    def fetch_request_token(request_token_url, method = :post)
      return if has_request_token?

      res = send(method, request_token_url)

      opts = {}
      res.split('&').map { |str| str.split('=') }.each { |k, v| opts[k] = v }

      self.token = opts['oauth_token']
      self.token_secret = opts['oauth_token_secret']

      opts
    end

    def fetch_access_token(access_token_url, method = :post)
      return unless has_request_token?

      res = send(method, access_token_url)

      opts = {}
      res.split('&').map { |str| str.split('=') }.each { |k, v| opts[k] = v }

      self.token = opts['oauth_token']
      self.token_secret = opts['oauth_token_secret']

      opts
    end
  end
end
