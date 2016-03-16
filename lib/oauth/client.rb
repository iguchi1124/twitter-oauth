# frozen_string_literal: true

# Standard Libraries
require 'net/http'
require 'openssl'
require 'uri'

module OAuth
  class Client
    include OAuth::Header

    def initialize(opts = {})
      yield self if block_given?

      self.consumer_key    ||= opts['consumer_key']
      self.consumer_secret ||= opts['consumer_secret']

      self.signature_method ||= 'HMAC-SHA1'
      self.callback         ||= opts['callback'] || 'oob'
    end

    def get(url, opts = {})
      @request_url = url
      @request_method = :get
      @options = opts
      reset_onetime_params!

      uri = URI(request_url)
      uri.query = normalized_signed_params
      uri.query += '&' + opts.collect { |k, v| "#{k}=#{v}" }.join('&') unless opts.nil?

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true if uri.port == 443

      req = Net::HTTP::Get.new(uri)

      res = http.request(req)
      res.body
    end

    def post(url, opts = {})
      @request_url = url
      @request_method = :post
      @options = opts
      reset_onetime_params!

      uri = URI(@request_url)

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true if uri.port == 443

      req = Net::HTTP::Post.new(uri)
      req['Authorization'] = authorization_header
      req.body = opts.collect { |k, v| "#{k}=#{v}" }.join('&') unless opts.nil?

      res = http.request(req)
      res.body
    end

    def fetch_request_token(request_token_url, method = :post)
      return if has_request_token?

      res = send(method, request_token_url)

      opts = {}
      res.split('&').map { |str| str.split('=') }.each { |k, v| opts[k] = v }

      self.request_token = opts['oauth_token']
      self.request_token_secret = opts['oauth_token_secret']

      define_singleton_accessor(:pin) if callback == 'oob'

      opts
    end

    def fetch_access_token(access_token_url, method = :post)
      return if has_access_token? || !has_request_token?

      res = send(method, access_token_url)

      opts = {}
      res.split('&').map { |str| str.split('=') }.each { |k, v| opts[k] = v }

      self.access_token = opts['oauth_token']
      self.access_token_secret = opts['oauth_token_secret']

      opts
    end

    private

    def define_singleton_accessor(name)
      name = name.to_s
      define_singleton_method(:"#{name}") { eval "@#{name}" }
      define_singleton_method(:"#{name}=") { |val| eval "@#{name} = val" }
    end
  end
end
