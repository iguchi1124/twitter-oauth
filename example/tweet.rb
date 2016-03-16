# frozen_string_literal: true

# RubyGems
require 'bundler'
Bundler.require

require_relative '../lib/oauth/header'
require_relative '../lib/oauth/client'
require 'yaml'

client = OAuth::Client.new(YAML.load_file('secrets.yml'))
client.fetch_request_token('https://api.twitter.com/oauth/request_token')
print "次のURLで認証して下さい: https://api.twitter.com/oauth/authorize?oauth_token=#{client.request_token}\n"
print "PINコードを入力して下さい: "
client.pin = gets.chomp
client.fetch_access_token('https://api.twitter.com/oauth/access_token')
puts client.post('https://api.twitter.com/1.1/statuses/update.json', status: 'tweet test')
