require 'spec_helper'
require 'puppet/type/package'
require 'puppet/provider/winrmssl/ruby_openssl.rb'

describe Puppet::Type.type(:winrmssl).provider(:ruby_openssl) do
  let(:resource) { Puppet::Type.type(:winrmssl).new(provider: 'ruby_openssl', name: 'spectest') }
  let(:provider_class) { subject.class }
  let(:provider) { subject.class.new(resource) }
  let(:auth_default) do
    <<-EOT
    Auth
        Basic = false
        Kerberos = true
        Negotiate = true
        Certificate = false
        CredSSP = false
        CbtHardeningLevel = Relaxed
    EOT
  end
  let(:listener_default) do
    <<-EOT
    Listener
        Address = *
        Transport = HTTP
        Port = 5985
        Hostname
        Enabled = true
        URLPrefix = wsman
    EOT
  end
  let(:winrs_default) do
    <<-EOT
    winrs
        AllowRemoteShellAccess = true
        IdleTimeout = 72000000
        MaxConcurrentUsers = 10
        MaxShellRunTime = 2147483647
        MaxProcessesPerShell = 25
        MaxMemoryPerShellMB = 512
        MaxShellsPerUser = 30
    EOT
  end

  before :each do
    resource.provider = provider

    # Stub all file and config tests
    allow(Puppet::Util::Execution).to receive(:execute)
  end

  it 'has an _thumbprint method' do
    expect(provider).to respond_to(:_thumbprint)
  end

  # Listener endpoint
  it 'returns something if HTTP transport is set and not HTTPS, and says port is blank' do
    allow(provider).to receive(:exec_call).and_return(listener_default, 0)
    expect(provider.disable_http).to eq(:false)
  end
  it 'returns blank if listener is HTTP only' do
    allow(provider).to receive(:exec_call).and_return(listener_default, 0)
    expect(provider.port).to eq('')
  end

  # Auth endpoint
  it 'returns false if Basic is not specified' do
    allow(provider).to receive(:exec_call).and_return(auth_default, 0)
    expect(provider.auth_basic).to eq(:false)
  end
  it 'returns the credSSP value' do
    allow(provider).to receive(:exec_call).and_return(auth_default, 0)
    expect(provider.auth_credssp).to eq(:false)
  end
  it 'returns the kerberos value' do
    allow(provider).to receive(:exec_call).and_return(auth_default, 0)
    expect(provider.auth_kerberos).to eq(:true)
  end
  it 'returns the authnegotiate value' do
    allow(provider).to receive(:exec_call).and_return(auth_default, 0)
    expect(provider.auth_negotiate).to eq(:true)
  end

  # winrs endpoint
  it 'returns the max memory per shell' do
    allow(provider).to receive(:exec_call).and_return(winrs_default, 0)
    expect(provider.maxmemorypershellmb).to eq('512')
  end

  # setters
  # it 'successfully disables HTTP' do
  #  allow(provider).to receive(:exec_call).and_return('ResourceCreated', 1)
  #  expect(provider.disable_http).to eq(:true)
  #  expect(provider.disable_http).to eq(0)
  # end
end
