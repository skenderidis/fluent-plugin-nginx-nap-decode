require "helper"
require "fluent/plugin/filter_nginx_nap_decode.rb"

class NginxNapDecodeFilterTest < Test::Unit::TestCase
  setup do
    Fluent::Test.setup
  end

  test "failure" do
    flunk
  end

  private

  def create_driver(conf)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::NginxNapDecodeFilter).configure(conf)
  end
end
