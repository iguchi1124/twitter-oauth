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

      @consumer_key    ||= opts['consumer_key']
      @consumer_secret ||= opts['consumer_secret']

      @signature_method ||= 'HMAC-SHA1'
      @callback         ||= opts['callback'] || 'oob'
    end

    def set_request_params(verb, url, opts = {})
      @request_method = verb
      @request_url = url
      @options = opts
      reset_onetime_params!
    end

    def get(url, opts = {})
      set_request_params('GET', url, opts.each { |k, v| opts[k] = URI.encode(v.to_s) })

      uri = URI(@request_url)
      uri.query = normalized_signed_params
      uri.query += '&' + @options.collect { |k, v| "#{k}=#{v}" }.join('&') unless @options.nil?

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true if uri.port == 443

      req = Net::HTTP::Get.new(uri)

      res = http.request(req)
      res.body
    end

    def post(url, opts = {})
      set_request_params('POST', url, opts.each { |k, v| opts[k] = URI.encode(v.to_s) })

      uri = URI(@request_url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true if uri.port == 443

      req = Net::HTTP::Post.new(uri)
      req['Authorization'] = authorization_header
      req.body = @options.collect { |k, v| "#{k}=#{v}" }.join('&') unless @options.nil?

      res = http.request(req)
      res.body
    end

    def fetch_request_token(request_token_url, method = 'POST')
      return if has_request_token?

      res = send(method.downcase.to_sym, request_token_url)

      opts = {}
      res.split('&').map { |str| str.split('=') }.each { |k, v| opts[k] = v }

      @request_token = opts['oauth_token']
      @request_token_secret = opts['oauth_token_secret']

      define_singleton_accessor(:pin) if callback == 'oob'

      opts
    end

    def fetch_access_token(access_token_url, method = 'POST')
      return if has_access_token? || !has_request_token?

      res = send(method.downcase.to_sym, access_token_url)

      opts = {}
      res.split('&').map { |str| str.split('=') }.each { |k, v| opts[k] = v }

      @access_token = opts['oauth_token']
      @access_token_secret = opts['oauth_token_secret']

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
