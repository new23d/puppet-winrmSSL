# winrmSSL

Setup WinRM over HTTPS and control some basic, essential settings. Also supports Puppet CA issued certificates if using [puppetlabs/windows_puppet_certificates](https://forge.puppet.com/puppetlabs/windows_puppet_certificates).

### Parameters

`issuer` can be set to either the value of the "Issued By" field of the certificate to utilise, or the path to the certificate issuer's/authority's .PEM public certificate file.

`port` (default 5986) This is for HTTPS only.

`maxmemoryshellpermb` (default 1024) As per the WinRM setting. You may need to apply Microsoft KB2842230 for this to take effect.

`maxtimeoutms` (default 60000) As per the WinRM setting.

`auth_basic` (default true) Since you are HTTPS secured now, no harm in allowing Basic Auth.

`auth_negotiate` (default true) Manages Negotiate authentication.

`auth_kerberos` (default true) Manages Kerberos authentication.

`auth_credssp` (default false) Manages CredSSP authentication.

`disable_http` (default true) Removes the HTTP listener completely from WinRM so that plaintext transport is simply not available.

### Examples

Note that the following example uses the `new23d-puppetpem2p12` module for the `puppet_config_localcacert` fact.

```
# read the path to the Puppet CA's .PEM file into a variable
$ca_to_trust = $::puppet_config_localcacert

winrmssl {$ca_to_trust:
  ensure => present,
  issuer => $ca_to_trust,
  #port                => 5986,
  #maxmemorypershellmb => 1024,
  #maxtimeoutms        => 60000,
  #auth_basic          => true,
  #auth_negotiate      => true,
  #auth_kerberos       => true,
  #auth_credssp        => false,
  #disable_http        => true
}
```

