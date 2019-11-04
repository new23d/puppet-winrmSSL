# winrmssl

Setup WinRM over HTTPS and control some basic, essential settings. Also supports Puppet CA issued certificates if using [puppetlabs/windows_puppet_certificates](https://forge.puppet.com/puppetlabs/windows_puppet_certificates).

## Usage

Will configure winrm to use HTTPS from a certificate existing in the certstore.

You can choose to provide a .PEM file that openssl can read to match issuer with one in the cert store (much like how `windows_puppet_certificates` bootstraps), or provide the Issuer name of a certificate already in the local machine's certstore.

If you are using Puppet with a Master, you can easily leverage Puppet's CA and individual machine certs instead of issuing a certificate to each system with your org's primary CA.

Powershell command that could be used as a fact to grab a specific certificate's issuer shown below:

```powershell
Get-ChildItem Cert:\LocalMachine\Root\ABC123DEF456GHI | Select -ExpandProperty Issuer
```

Any parameters not set will revert to their default value by winrm.

```puppet
winrmssl { 'CN=Example Issuer CA Authority, OU=Example Corp, OU=Test':
  ensure => present,
}
```

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

Note that the following example uses the []windows_puppet_certificates(https://forge.puppet.com/puppetlabs/windows_puppet_certificates) module for the `ca_path` fact.

```
# read the path to the Puppet CA's .PEM file into a variable
$ca_to_trust = $facts['puppet_cert_paths']['ca_path']

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

