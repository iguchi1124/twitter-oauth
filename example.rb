require_relative 'oauth'
require 'yaml'

client = OAuth.new(YAML.load_file('secrets.yml'))
puts client.token if client.set_token('https://api.twitter.com/oauth/request_token')
