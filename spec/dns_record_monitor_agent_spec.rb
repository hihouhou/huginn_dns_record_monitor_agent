require 'rails_helper'
require 'huginn_agent/spec_helper'

describe Agents::DnsRecordMonitorAgent do
  before(:each) do
    @valid_options = Agents::DnsRecordMonitorAgent.new.default_options
    @checker = Agents::DnsRecordMonitorAgent.new(:name => "DnsRecordMonitorAgent", :options => @valid_options)
    @checker.user = users(:bob)
    @checker.save!
  end

  pending "add specs here"
end
