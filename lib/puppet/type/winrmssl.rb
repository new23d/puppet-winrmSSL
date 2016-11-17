Puppet::Type.newtype(:winrmssl) do
  ensurable

  newparam(:issuer, namevar: true) do
  end

  newproperty(:disable_http) do
    newvalues(:true, :false)
    defaultto :true
  end

  newproperty(:port) do
    defaultto '5986'
  end

  newproperty(:auth_basic) do
    newvalues(:true, :false)
    defaultto :true
  end

  newproperty(:maxmemorypershellmb) do
    defaultto '1024'
  end

  newproperty(:maxtimeoutms) do
    defaultto '60000'
  end

  newproperty(:certificatethumbprint) do
    defaultto ''
  end
end
