require 'spec_helper'

describe OAuth::Header do
  include OAuth::Header

  describe '#percent_encode' do
    let(:str) { 'encoding string+?/=' }
    it do
      require 'cgi'
      expect(CGI.escape str).to eq percent_encode(str)
    end
  end

  describe '#base64_encode' do
    let(:str) { 'encoding string+?/=' }
    it do
      require 'base64'
      expect(Base64.encode64 str).to eq base64_encode(str)
    end
  end
end