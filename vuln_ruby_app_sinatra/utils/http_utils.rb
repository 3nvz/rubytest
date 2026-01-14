require "net/http"
require "uri"

module HttpUtils
  def self.fetch_url(url)
    perform_request(url)
  end

  def self.perform_request(url)
    uri = URI.parse(url)
    Net::HTTP.get(uri)
  end
end