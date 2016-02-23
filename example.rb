require_relative 'oauth'
require 'yaml'

client = OAuth.new(YAML.load_file('secrets.yml'))
puts client.post('https://api.twitter.com/oauth/request_token')
puts client.get('https://api.twitter.com/oauth/request_token')
