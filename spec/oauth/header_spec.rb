require 'spec_helper'

RSpec.configure do |config|
  config.include OAuth::Header
end

describe OAuth::Header do
  let(:str) { 'str :?/=' }

  describe '#percent_encode' do
    it do
      require 'cgi'
      expect(CGI.escape(str)).to eq(percent_encode(str))
    end
  end

  describe '#base64_encode' do
    it do
      require 'base64'
      expect(Base64.encode64(str).delete("\n")).to eq(base64_encode(str))
    end
  end
end