require 'openssl'
require 'open3'

Puppet::Type.type(:winrmssl).provide(:ruby_openssl) do
  confine osfamily: :windows

  # helpers
  def exec_call(var_cmd)
    stdout_str, status = Open3.capture2(var_cmd)
    [stdout_str, status.exitstatus]
  end

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
    # handle double quotes with wildcards if they exist.
    issuer_subject.gsub!(%r{^CN=}, 'CN=*')
    issuer_subject.gsub!(%r{^.*$}, '\&*')

    var_cmd = "powershell @(get-childitem certificate::localmachine/my ^| where-object { $_.issuer -like '#{issuer_subject}'" \
      " -and $_.subject -eq 'CN=#{Facter['fqdn'].value}' -and $_.hasprivatekey} ^| sort-object -property notafter -descending)[0].thumbprint"
    stdout_str, = exec_call(var_cmd)
    var_stdout_raw = stdout_str
    var_stdout_raw.strip!

    if var_stdout_raw.empty?
      var_thumbprint = ''
      raise Puppet::ResourceError, "Could not find a valid certificate for '#{Facter['fqdn'].value}' issued by '#{issuer_subject}'."
    else
      var_thumbprint = var_stdout_raw
    end

    var_thumbprint
  end

  # getters
  def certificatethumbprint
    var_cmd = 'winrm.cmd enumerate winrm/config/listener'
    var_rgx = %r{CertificateThumbprint = ([0-9A-F]{40,40})$}

    stdout_str, = exec_call(var_cmd)

    rgx_mth = var_rgx.match(stdout_str)
    var_state = if !rgx_mth.nil?
                  rgx_mth[1]
                else
                  ''
                end

    var_state
  end

  def disable_http
    var_cmd = 'winrm.cmd enumerate winrm/config/listener'
    var_rgx = %r{Transport = HTTP$}

    stdout_str, = exec_call(var_cmd)

    rgx_mth = var_rgx.match(stdout_str)
    var_state = rgx_mth.nil?

    var_state = var_state.to_s.to_sym

    var_state
  end

  def port
    var_cmd = 'winrm.cmd enumerate winrm/config/listener'
    var_rgx = %r{Transport = HTTPS\n[ ]{1,}Port = ([0-9]{1,5})$}

    stdout_str, = exec_call(var_cmd)

    rgx_mth = var_rgx.match(stdout_str)
    var_state = if !rgx_mth.nil?
                  rgx_mth[1]
                else
                  ''
                end

    var_state
  end

  def auth_basic
    var_cmd = 'winrm.cmd get winrm/config/service/auth'
    var_rgx = %r{Basic = true$}

    stdout_str, = exec_call(var_cmd)
    rgx_mth = var_rgx.match(stdout_str)
    var_state = !rgx_mth.nil?

    var_state = var_state.to_s.to_sym

    var_state
  end

  def auth_credssp
    var_cmd = 'winrm.cmd get winrm/config/service/auth'
    var_rgx = %r{CredSSP = true$}

    stdout_str, = exec_call(var_cmd)
    rgx_mth = var_rgx.match(stdout_str)
    var_state = !rgx_mth.nil?

    var_state = var_state.to_s.to_sym

    var_state
  end

  def auth_kerberos
    var_cmd = 'winrm.cmd get winrm/config/service/auth'
    var_rgx = %r{Kerberos = true$}

    stdout_str, = exec_call(var_cmd)
    rgx_mth = var_rgx.match(stdout_str)
    var_state = !rgx_mth.nil?

    var_state = var_state.to_s.to_sym

    var_state
  end

  def auth_negotiate
    var_cmd = 'winrm.cmd get winrm/config/service/auth'
    var_rgx = %r{Negotiate = true$}

    stdout_str, = exec_call(var_cmd)

    rgx_mth = var_rgx.match(stdout_str)
    var_state = !rgx_mth.nil?

    var_state = var_state.to_s.to_sym

    var_state
  end

  def maxmemorypershellmb
    var_cmd = 'winrm.cmd get winrm/config/winrs'
    var_rgx = %r{MaxMemoryPerShellMB = ([0-9]{1,})$}

    stdout_str, = exec_call(var_cmd)

    rgx_mth = var_rgx.match(stdout_str)
    var_state = if !rgx_mth.nil?
                  rgx_mth[1]
                else
                  ''
                end

    var_state
  end

  def maxtimeoutms
    var_cmd = 'winrm.cmd get winrm/config'
    var_rgx = %r{MaxTimeoutms = ([0-9]{1,})$}

    stdout_str, = exec_call(var_cmd)

    rgx_mth = var_rgx.match(stdout_str)
    var_state = if !rgx_mth.nil?
                  rgx_mth[1]
                else
                  ''
                end

    var_state
  end

  ## setters
  def disable_http=(var_param)
    var_cmd = if var_param == :true
                'winrm delete winrm/config/listener?Address=*+Transport=HTTP'
              else
                'winrm create winrm/config/listener?Address=*+Transport=HTTP'
              end

    _, exitstatus = exec_call(var_cmd)
    exitstatus
  end

  def port=(_var_param)
    destroy
    create
  end

  def auth_basic=(var_param)
    var_cmd = "winrm set winrm/config/service/auth @{Basic=\"#{var_param}\"}"
    _, exitstatus = exec_call(var_cmd)
    exitstatus
  end

  def auth_credssp=(var_param)
    var_cmd = "winrm set winrm/config/service/auth @{CredSSP=\"#{var_param}\"}"
    _, exitstatus = exec_call(var_cmd)
    exitstatus
  end

  def auth_kerberos=(var_param)
    var_cmd = "winrm set winrm/config/service/auth @{Kerberos=\"#{var_param}\"}"
    _, exitstatus = exec_call(var_cmd)
    exitstatus
  end

  def auth_negotiate=(var_param)
    var_cmd = "winrm set winrm/config/service/auth @{Negotiate=\"#{var_param}\"}"
    _, exitstatus = exec_call(var_cmd)
    exitstatus
  end

  def maxmemorypershellmb=(var_param)
    var_cmd = "winrm set winrm/config/winrs @{MaxMemoryPerShellMB=\"#{var_param}\"}"
    _, exitstatus = exec_call(var_cmd)
    exitstatus
  end

  def maxtimeoutms=(var_param)
    var_cmd = "winrm set winrm/config @{MaxTimeoutms=\"#{var_param}\"}"
    _, exitstatus = exec_call(var_cmd)
    exitstatus
  end

  def certificatethumbprint=(_var_param)
    # ignore the passed-in value

    var_thumbprint = _thumbprint

    var_cmd = "winrm create winrm/config/listener?Address=*+Transport=HTTPS @{Hostname=\"#{Facter['fqdn'].value}\";CertificateThumbprint=\"#{var_thumbprint}\";Port=\"#{@resource[:port]}\"}"
    _, exitstatus = exec_call(var_cmd)
    exitstatus
  end

  ## implements
  def create
    var_properties2ignore = [caller_locations(1, 1)[0].label]

    @resource.properties.each do |var_property|
      next unless respond_to? "#{var_property}=".to_sym

      # don't recurse into the caller!
      next unless (!var_properties2ignore.include? var_property.to_s) && (!var_properties2ignore.include? "#{var_property}=")

      next unless send(var_property.to_s) != @resource[var_property.to_s.to_sym]

      send("#{var_property}=", @resource[var_property.to_s.to_sym])
    end
  end

  def destroy
    var_cmd = 'winrm.cmd invoke restore winrm/config @{}'
    _, exitstatus = exec_call(var_cmd)
    exitstatus
  end

  def exists?
    @resource[:certificatethumbprint] = _thumbprint

    var_cmd = 'winrm.cmd enumerate winrm/config/listener'
    var_rgx = %r{Transport = HTTPS\n[ ]{1,}Port = #{@resource[:port]}\n}
    var_stdout, = exec_call(var_cmd)

    rgx_mth = var_rgx.match(var_stdout)
    var_rc = !rgx_mth.nil?

    var_rc
  end

  def self.instances
    raise 'Not implemented.'
  end
end
