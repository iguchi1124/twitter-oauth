require_relative 'oauth'
require 'yaml'

client = OAuth.new(YAML.load_file('secrets.yml'))
client.get_request_token('https://api.twitter.com/oauth/request_token')
print "次のURLで認証して下さい: https://api.twitter.com/oauth/authorize?oauth_token=#{client.token}\n"
print "PINコードを入力して下さい: "
client.pin = gets
puts client.get_access_token('https://api.twitter.com/oauth/access_token')
