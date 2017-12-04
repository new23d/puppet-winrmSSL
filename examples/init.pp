# Note - This assumes your Puppet Master CA is already in the trusted store.
# Trusted store isn't handled by this module yet.
winrmssl { 'C:\ProgramData\PuppetLabs\puppet\etc\ssl\certs\ca.pem':
  ensure => present,
}
