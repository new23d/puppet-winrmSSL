require 'openssl'
require 'open3'

Puppet::Type.type(:winrmssl).provide(:ruby_openssl) do
  ## confines
  confine osfamily: 'windows'

  ## helpers
  def _thumbprint
    # is the namevar/issuer a Filesystem Path, or a Distinguished Name (DN)?
    var_issuer_in_file = File.exist?(@resource[:issuer])

    if var_issuer_in_file
      issuer_pem = File.read(@resource[:issuer])

      issuer_openssl_cert = OpenSSL::X509::Certificate.new(issuer_pem)
      issuer_subject = issuer_openssl_cert.subject.to_s
    else
      # assuming it's a DN
      issuer_subject = @resource[:issuer]
    end

    # remove leading slash if found
    issuer_subject.gsub!(%r{^(\/)(.*)$}, '\2')

    # var_cmd = "powershell @(get-childitem certificate::localmachine/my ^| where-object { $_.issuer -eq '#{issuer_subject}' -and $_.dnsnamelist -contains '#{Facter['fqdn'].value}' -and $_.hasprivatekey -and $_.enhancedkeyusagelist.friendlyname -contains 'Server Authentication'} ^| sort-object -property notafter -descending} )[0].thumbprint"
    # var_cmd = "powershell @(get-childitem certificate::localmachine/my ^| where-object { $_.issuer -eq '#{issuer_subject}' -and $_.dnsnamelist -contains '#{Facter['fqdn'].value}' -and $_.hasprivatekey -and $_.enhancedkeyusagelist.objectid -contains '1.3.6.1.5.5.7.3.1'} ^| sort-object -property notafter -descending)[0].thumbprint"
	var_cmd = "powershell @(get-childitem certificate::localmachine/my ^| where-object { $_.issuer -eq '#{issuer_subject}' -and $_.subject -eq 'CN=#{Facter['fqdn'].value}' -and $_.hasprivatekey} ^| sort-object -property notafter -descending)[0].thumbprint"
    stdin, stdout, stderr, wait_thr = Open3.popen3(var_cmd)
	stdin.close
    var_rc = wait_thr.value.exitstatus
    var_stdout_raw = stdout.read
    var_stdout_raw.strip!

    if var_stdout_raw.empty?
      var_thumbprint = ''
      fail Puppet::ResourceError, "Could not find a valid certificate for '#{Facter['fqdn'].value}' issued by '#{issuer_subject}'."
    else
      var_thumbprint = var_stdout_raw
    end

    var_thumbprint
  end

  ## getters
  def certificatethumbprint
    var_cmd = 'winrm.cmd enumerate winrm/config/listener'
    var_rgx = %r{CertificateThumbprint = ([0-9A-F]{40,40})$}

    stdin, stdout, stderr, wait_thr = Open3.popen3(var_cmd)
    stdin.close
    var_rc = wait_thr.value.exitstatus
    var_stdout = stdout.read

    rgx_mth = var_rgx.match(var_stdout)
    if !rgx_mth.nil?
      var_state = rgx_mth[1]
    else
      var_state = ''
    end

    var_state
  end

  def disable_http
    var_cmd = 'winrm.cmd enumerate winrm/config/listener'
    var_rgx = %r{Transport = HTTP$}

    stdin, stdout, stderr, wait_thr = Open3.popen3(var_cmd)
    stdin.close
    var_rc = wait_thr.value.exitstatus
    var_stdout = stdout.read

    rgx_mth = var_rgx.match(var_stdout)
    var_state = (rgx_mth.nil?)

    var_state = var_state.to_s.intern

    var_state
  end

  def port
    var_cmd = 'winrm.cmd enumerate winrm/config/listener'
    var_rgx = %r{Transport = HTTPS\n[ ]{1,}Port = ([0-9]{1,5})$}

    stdin, stdout, stderr, wait_thr = Open3.popen3(var_cmd)
    stdin.close
    var_rc = wait_thr.value.exitstatus
    var_stdout = stdout.read

    rgx_mth = var_rgx.match(var_stdout)
    if !rgx_mth.nil?
      var_state = rgx_mth[1]
    else
      var_state = ''
    end

    var_state
  end

  def auth_basic
    var_cmd = 'winrm.cmd get winrm/config/service/auth'
    var_rgx = %r{Basic = true$}

    stdin, stdout, stderr, wait_thr = Open3.popen3(var_cmd)
    stdin.close
    var_rc = wait_thr.value.exitstatus
    var_stdout = stdout.read

    rgx_mth = var_rgx.match(var_stdout)
    var_state = (!rgx_mth.nil?)

    var_state = var_state.to_s.intern

    var_state
  end

  def maxmemorypershellmb
    var_cmd = 'winrm.cmd get winrm/config/winrs'
    var_rgx = %r{MaxMemoryPerShellMB = ([0-9]{1,})$}

    stdin, stdout, stderr, wait_thr = Open3.popen3(var_cmd)
    stdin.close
    var_rc = wait_thr.value.exitstatus
    var_stdout = stdout.read

    rgx_mth = var_rgx.match(var_stdout)
    if !rgx_mth.nil?
      var_state = rgx_mth[1]
    else
      var_state = ''
    end

    var_state
  end

  def maxtimeoutms
    var_cmd = 'winrm.cmd get winrm/config'
    var_rgx = %r{MaxTimeoutms = ([0-9]{1,})$}

    stdin, stdout, stderr, wait_thr = Open3.popen3(var_cmd)
    stdin.close
    var_rc = wait_thr.value.exitstatus
    var_stdout = stdout.read

    rgx_mth = var_rgx.match(var_stdout)
    if !rgx_mth.nil?
      var_state = rgx_mth[1]
    else
      var_state = ''
    end

    var_state
  end

  ## setters
  def disable_http=(var_param)
    if var_param == :true
      var_cmd = 'winrm delete winrm/config/listener?Address=*+Transport=HTTP'
    else
      var_cmd = 'winrm create winrm/config/listener?Address=*+Transport=HTTP'
    end

    stdin, stdout, stderr, wait_thr = Open3.popen3(var_cmd)
    stdin.close
    var_rc = wait_thr.value.exitstatus
  end

  def port=(_var_param)
    destroy
    create
  end

  def auth_basic=(var_param)
    var_cmd = "winrm set winrm/config/service/auth @{Basic=\"#{var_param}\"}"
    stdin, stdout, stderr, wait_thr = Open3.popen3(var_cmd)
    stdin.close
    var_rc = wait_thr.value.exitstatus
  end

  def maxmemorypershellmb=(var_param)
    var_cmd = "winrm set winrm/config/winrs @{MaxMemoryPerShellMB=\"#{var_param}\"}"
    stdin, stdout, stderr, wait_thr = Open3.popen3(var_cmd)
    stdin.close
    var_rc = wait_thr.value.exitstatus
  end

  def maxtimeoutms=(var_param)
    var_cmd = "winrm set winrm/config @{MaxTimeoutms=\"#{var_param}\"}"
    stdin, stdout, stderr, wait_thr = Open3.popen3(var_cmd)
    stdin.close
    var_rc = wait_thr.value.exitstatus
  end

  def certificatethumbprint=(_var_param)
    # ignore the passed-in value

    var_thumbprint = _thumbprint

    var_cmd = "winrm create winrm/config/listener?Address=*+Transport=HTTPS @{Hostname=\"#{Facter['fqdn'].value}\";CertificateThumbprint=\"#{var_thumbprint}\";Port=\"#{@resource[:port]}\"}"
    stdin, stdout, stderr, wait_thr = Open3.popen3(var_cmd)
    stdin.close
    var_rc = wait_thr.value.exitstatus
  end

  ## implements
  def create
    var_properties2ignore = [caller_locations(1, 1)[0].label]

    @resource.properties.each do |var_property|
      next unless self.respond_to? "#{var_property}=".intern

      # don't recurse into the caller!
      next unless (!var_properties2ignore.include? var_property.to_s) && (!var_properties2ignore.include? "#{var_property}=")

      next unless send("#{var_property}") != @resource["#{var_property}".intern]

      send("#{var_property}=", @resource["#{var_property}".intern])
    end
  end

  def destroy
    var_cmd = 'winrm.cmd invoke restore winrm/config @{}'
    stdin, stdout, stderr, wait_thr = Open3.popen3(var_cmd)
    stdin.close
    var_rc = wait_thr.value.exitstatus
  end

  def exists?
    @resource[:certificatethumbprint] = _thumbprint

    var_cmd = 'winrm.cmd enumerate winrm/config/listener'
    var_rgx = %r{Transport = HTTPS\n[ ]{1,}Port = #{@resource[:port]}\n}

    stdin, stdout, stderr, wait_thr = Open3.popen3(var_cmd)
    stdin.close
    var_rc = wait_thr.value.exitstatus
    var_stdout = stdout.read

    rgx_mth = var_rgx.match(var_stdout)
    var_rc = (!rgx_mth.nil?)

    var_rc
  end

  def self.instances
    fail 'Not implemented.'
  end
end
