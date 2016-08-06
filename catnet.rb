#!/usr/bin/env ruby
# Kent 'picat' Gruber
#____________________________________________________
#               |                                    |
#  C A T N E T  |                 /\       policy_/\ |
#      t o      | _ __/|  sniff  /  \        /\  /  \|
#   c a t c h   | \'o.0'- sniff /    \/\    /  \/    |
#       a       |__(\/_)/______/        \  /         |
#  N E T C A T  |                 policy_\/          |
#_______________|____________________________________|
#
# This command-line application is sort'of confusingly
# named. I'm ok with this. This application is meant
# to help monitor IPv4 connections similar to the way
# the netstat command works including ascii art,
# colors ( including rainbows ), logs, and custom
# policies for interacting or responding to information.
# Very effective for understanding tcp/udp IPv4 communications
# for linux distributions. Software is as-is and I am 
# not responsible for any damge caused using it in any form.
#
# Use at your own risk, and be safe!
#
# Author::    Kent 'picat' Gruber
# Copyright:: Copyright (c) 2016 Kent Gruber
# License::   MIT

require 'yaml'
require 'colorize'
require 'celluloid/current'
require 'logger'
require 'optparse'

def banner
  print "\n_ __/|  sniff
\\'o.0'- sniff 
 (\\/_)/"
  puts "\nCATNET -- IPv4 TCP/UDP Network Connection Monitor".bold.red
end

def cls
  system('clear')
end

options = {}
options[:verbose] = false
options[:listen] = false
options[:start] = false
options[:monitor] = false
options[:banner] = false
options[:policy] = false
options[:config] = false
options[:debug] = false
options[:notify] = false
options[:log] = false
options[:protocols] = []
protocols = %w(tcp udp)
optparse = OptionParser.new do |opts|
  opts.separator ''
  protocols.each do |protocol|
    opts.on("-#{protocol[0, 1]}", '--' + protocol, "show #{protocol} connections only") do |option|
      options[:protocols] << protocol if option
    end
  end
  opts.on('-s', '--start', 'start application with defaults') do
    options[:start] = true
  end
  opts.on('-m', '--monitor', 'start application in monitor mode') do
    options[:monitor] = true
  end
  opts.on('-n', '--notify', 'use notifications if avaiable') do
    require 'notify'
    options[:notify] = true
  end
  opts.on('-b', '--[no-]banner', 'use cool ascii cat banner') do |banner|
    options[:banner] = banner
  end
  opts.on('-p', '--policy <FILE.yaml>', 'define a policy to use') do |file|
    options[:policy] = file
  end
  opts.on('-C', '--config <FILE.yaml>', 'define a custom config to use') do |file|
    options[:config] = file
  end
  opts.on('-L', '--[no-]log', 'Choose to use logging ( off default ).') do
    options[:log] = true
  end
  opts.on('-D', '--debug', 'Enter a debug mode with pry.') do
    options[:debug] = true
  end
  opts.on('-v', '--verbose', 'verbose output') do
    options[:verbose] = true
  end
  opts.on('-l', '--listen', 'only show ports which are listening') do
    options[:listen] = true
  end
  opts.on('-r', '--rainbow', 'rainbow support, because we need it.') do
    require 'lolize/auto'
  end
end

begin
  foo = ARGV[0] || ARGV[0] = '-h'
  optparse.parse!
rescue OptionParser::InvalidOption, OptionParser::MissingArgument
  cls
  banner
  puts
  puts $ERROR_INFO.to_s
  puts
  puts optparse
  puts
  exit 1
end

if options[:config]
  if File.readable?(options[:config])
    @config = YAML.load_file(options[:config])
  else
    raise "ERROR! Config file #{options[:config]} is not readable/dosen't exist."
  end
else
  @config = false
end

# This module handles the logging aspect
# of this application. Logging is not on
# by default and is saved to a file called
# 'catnet.log' in the current working 
# directory of the application.

module Logging
  def logger
    Logging.logger
  end

  def self.logger
    if @config
      if @config['log_file']
        # use config file if it exists
        @logger ||= Logger.new @config['log_file']
      end
    else
      @logger ||= Logger.new 'catnet.log'
    end
  end
end

# This class performs the majority of the logic
# of this application. Handles iterating tcp,
# or udp connections; the options that affect
# the iteration process including policies and
# rudimentary filtering. Options are passed in
# to control pretty much everything. 

class Catnet

  include Logging
  include Celluloid 

  # Disable celluloid logging.
  Celluloid.logger = nil
  
  def initialize(options)
    @options = options
    @supress = true unless @options[:log] rescue false
    logger.info("STARTED CATNET WITH OPTIONS: #{options.map{|k,v| "#{k} = #{v}"}.join(', ')}") unless @supress
  end
  
  def pid_to_name(pid)
    begin
      name = File.readlink("/proc/#{pid}/exe")
    rescue
      name = 'none'
    end
    name
  end

  def socket_to_pid(socket)
    prc = Dir.glob("/proc/[0-9]*/fd/*").find { |fd| File.readlink(fd).include? "socket:[#{socket}]" rescue nil }
    pid = prc.scan(/\d+/).first unless prc.nil?
    if prc.nil?
      pid = 'none'
    end
    pid
  end

  def tcp_states 
    @tcp_states = {
        '00' => 'UNKNOWN    '.bold.red,
        'FF' => 'UNKNOWN    '.bold.red,
        '01' => 'ESTABLISHED'.bold.green,
        '02' => 'SYN_SENT   '.bold.blue,
        '03' => 'SYN_RECV   '.bold.blue,
        '04' => 'FIN_WAIT1  '.bold.yellow,
        '05' => 'FIN_WAIT2  '.bold.yellow,
        '06' => 'TIME_WAIT  '.bold.magenta,
        '07' => 'CLOSE      '.bold.cyan,
        '08' => 'CLOSE_WAIT '.bold.cyan,
        '09' => 'LAST_ACK   '.bold.white,
        '0A' => 'LISTEN     '.bold.red,
        '0B' => 'CLOSING    '.bold.cyan
    }
  end

  def single_entry_pattern
    Regexp.new(/^\s*\d+:\s+(.{8}):(.{4})\s+(.{8}):(.{4})\s+(.{2})/)
  end

  def process_data(data)
    if check_data_match(data)
      @data = data
      process_socket_inode
      process_pid
      process_name
      process_local_ip
      process_local_port
      process_remote_ip
      process_remote_port
      process_connection_state
    end
  end

  def check_data_match(data)
    @match = data.match(single_entry_pattern) rescue false
  end

  def process_socket_inode
    @socket_inode = @data.split[9]
  end

  def process_pid
    @pid = socket_to_pid(@socket_inode)
  end

  def process_name
    @name = pid_to_name(@pid)
  end

  def process_local_ip
    @local_ip = [@match[1].to_i(16)].pack('N').unpack('C4').reverse.join('.') if @match
  end

  def process_local_port
    @local_port = @match[2].to_i(16) if @match
  end

  def process_remote_ip
    @remote_ip = [@match[3].to_i(16)].pack('N').unpack('C4').reverse.join('.') if @match
  end

  def process_remote_port
    @remote_port  = @match[4].to_i(16) if @match
  end

  def process_connection_state
    @connection_state = tcp_states[@match[5]] if @match
  end

  def find_protocols
    @protocols = []
    if @options[:protocols].empty?
      @protocols = %w(tcp udp)
    else
      @options[:protocols].each do |protocol|
        @protocols << protocol
      end
    end
  end

  def read_protocol(protocol)
    @protocol_data = File.readlines('/proc/net/' + protocol).map(&:strip)
  end

  def find_required
    find_policy
    find_protocols
    find_config
  end

  def iterate_protocols
    @protocols.each do |protocol|
      puts "\n#{protocol} connections".bold
      read_protocol(protocol)
      @protocol_data.each do |data|
        next if data.match('sl  local_address rem_address')
          process_data(data)
          
          if @options[:listen]
            next unless @connection_state.gsub(/\e\[([;\d]+)?m/, '').strip == "LISTEN"
          end

          process_policy
          unless @supress
            logger.info("#{protocol} : #{@connection_state}\t #{@pid}:#{@name}\t #{@local_ip}:#{@local_port}\t <-->\t #{@remote_ip}:#{@remote_port}") if @match
          end
          puts "#{@connection_state}\t #{@pid}:#{@name}\t #{@local_ip}:#{@local_port}\t <-->\t #{@remote_ip}:#{@remote_port}" if @match
      end
    end
  end

  def monitor_mode
    find_required
    loop do
      trap("SIGINT") { puts "\n\nCTRL+C Detected! Monitor shutting down..."; exit 0; }
      iterate_protocols
      sleep 1
      cls
    end
  end

  def find_config
    if @options[:config]
      if File.readable?(@options[:config])
        @config = YAML.load_file(@options[:config])
      else
        raise "ERROR! Config file #{options[:config]} is not readable/dosen't exist."
      end
    end
  end

  def find_policy
    if @options[:policy]
      if File.readable?(@options[:policy])
        @policy = YAML.load_file(@options[:policy])
      else
        raise "ERROR! File #{options[:policy]} is not readable/dosen't exist."
      end
    end
  end

  def process_policy
    # process all policies
    process_names_policy
    process_local_ips
    process_local_ports
    process_remote_ips
    process_remote_ports
    process_pids
    process_connection_states
  end

  # process names policy
  def process_names_policy
    if @policy && @policy['names'][@name]
      if @policy['names'][@name]['replace']
        name = @policy['names'][@name]['replace']        
      else
        name = @name
      end

      if @options[:notify]
        if @policy['names'][@name]['notify']
          if @policy['names'][@name]['notify']['message']
            Notify.notify('CATNECTION', @policy['names'][@name]['notify']['message'])
          end
        end
      end    
    
      if @policy['names'][@name]['type']
        type = @policy['names'][@name]['type']
        if type.downcase.chr == 'g' # if good
          name = name.green
        elsif type.downcase.chr == 'w' # if warn
          name = name.yellow
        elsif type.downcase.chr == 'b' # if bad
          name = name.red
        end
      end

      @name = name
    end
  end

  # process local_ips policy
  def process_local_ips
    if @policy && @policy['local_ips'][@local_ip]
      if @policy['local_ips'][@local_ip]['replace']
        local_ip = @policy['local_ips'][@local_ip]['replace']        
      else
        local_ip = @local_ip
      end

      if @options[:notify]
        if @policy['local_ips'][@local_ip]['notify']
          if @policy['local_ips'][@local_ip]['notify']['message']
            Notify.notify('CATNECTION', @policy['local_ips'][local_ip]['notify']['message'])
          end
        end
      end
    
      if @policy['local_ips'][@local_ip]['type']
        type = @policy['local_ips'][@local_ip]['type']
        if type.downcase.chr == 'g' # if good
          local_ip = local_ip.green
        elsif type.downcase.chr == 'w' # if warn
          local_ip = local_ip.yellow
        elsif type.downcase.chr == 'b' # if bad
          local_ip = local_ip.red
        end
      end

      @local_ip = local_ip
    end
  end

  # process local_ports policy
  def process_local_ports
    if @policy && @policy['local_ports'][@local_port]
      if @policy['local_ports'][@local_port]['replace']
        local_port = @policy['local_ports'][@local_port]['replace']        
      else
        local_port = @local_port
      end

      if @options[:notify]
        if @policy['local_ports'][@local_port]['notify']
          if @policy['local_ports'][@local_port]['notify']['message']
            Notify.notify('CATNECTION', @policy['local_ports'][local_port]['notify']['message'])
          end
        end
      end
    
      if @policy['local_ports'][@local_port]['type']
        type = @policy['local_ports'][@local_port]['type']
        if type.downcase.chr == 'g' # if good
          local_port = local_port.green
        elsif type.downcase.chr == 'w' # if warn
          local_port = local_port.yellow
        elsif type.downcase.chr == 'b' # if bad
          local_port = local_port.red
        end
      end

      @local_port = local_port
    end
  end

  # process remote_ips policy
  def process_remote_ips
    if @policy && @policy['remote_ips'][@remote_ip]
      if @policy['remote_ips'][@remote_ip]['replace']
        remote_ip = @policy['remote_ips'][@remote_ip]['replace']        
      else
        remote_ip = @remote_ip
      end

      if @options[:notify]
        if @policy['remote_ips'][@remote_ip]['notify']
          if @policy['remote_ips'][@remote_ip]['notify']['message']
            Notify.notify('CATNECTION', @policy['remote_ips'][remote_ip]['notify']['message'])
          end
        end
      end
    
      if @policy['remote_ips'][@remote_ip]['type']
        type = @policy['remote_ips'][@remote_ip]['type']
        if type.downcase.chr == 'g' # if good
          remote_ip = remote_ip.green
        elsif type.downcase.chr == 'w' # if warn
          remote_ip = remote_ip.yellow
        elsif type.downcase.chr == 'b' # if bad
          remote_ip = remote_ip.red
        end
      end

      @remote_ip = remote_ip
    end
  end
  
  # process remote_ports policy
  def process_remote_ports
    if @policy && @policy['remote_ports'][@remote_port]
      if @policy['remote_ports'][@remote_port]['replace']
        remote_port = @policy['remote_ports'][@remote_port]['replace']        
      else
        remote_port = @remote_port
      end

      if @options[:notify]
        if @policy['remote_ports'][@remote_port]['notify']
          if @policy['remote_ports'][@remote_port]['notify']['message']
            Notify.notify('CATNECTION', @policy['remote_ports'][remote_port]['notify']['message'])
          end
        end
      end
    
      if @policy['remote_ports'][@remote_port]['type']
        type = @policy['remote_ports'][@remote_port]['type']
        if type.downcase.chr == 'g' # if good
          remote_port = remote_port.green
        elsif type.downcase.chr == 'w' # if warn
          remote_port = remote_port.yellow
        elsif type.downcase.chr == 'b' # if bad
          remote_port = remote_port.red
        end
      end

      @remote_port = remote_port
    end

  end

  # process pids policy
  def process_pids
    if @policy && @policy['pids'][@pid]
      if @policy['pids'][@pid]['replace']
        pid = @policy['pids'][@pid]['replace']        
      else
        pid = @pid
      end

      if @options[:notify]
        if @policy['pids'][@pid]['notify']
          if @policy['pids'][@pid]['notify']['message']
            Notify.notify('CATNECTION', @policy['pids'][pid]['notify']['message'])
          end
        end
      end
    
      if @policy['pids'][@pid]['type']
        type = @policy['pids'][@pid]['type']
        if type.downcase.chr == 'g' # if good
          pid = pid.green
        elsif type.downcase.chr == 'w' # if warn
          pid = pid.yellow
        elsif type.downcase.chr == 'b' # if bad
          pid = pid.red
        end
      end

      @pid = pid
    end
  end

  # process connection_states policy
  def process_connection_states
    if @policy && @policy['connection_states'][@connection_state]
      if @policy['connection_states'][@connection_state]['replace']
        connection_state = @policy['connection_states'][@connection_state]['replace']        
      else
        connection_state = @connection_state
      end

      if @options[:notify]
        if @policy['connection_states'][@connection_state]['notify']
          if @policy['connection_states'][@connection_state]['notify']['message']
            Notify.notify('CATNECTION', @policy['connection_states'][connection_state]['notify']['message'])
          end
        end
      end
    
      if @policy['connection_states'][@connection_state]['type']
        type = @policy['connection_states'][@connection_state]['type']
        if type.downcase.chr == 'g' # if good
          connection_state = connection_state.green
        elsif type.downcase.chr == 'w' # if warn
          connection_state = connection_state.yellow
        elsif type.downcase.chr == 'b' # if bad
          connection_state = connection_state.red
        end
      end

      @connection_state = connection_state
    end
  end
end

banner if options[:banner]

if options[:debug]
  require 'pry'
  binding.pry
  exit 0
end

if options[:monitor]
  sniffer = Catnet.new(options)
  sniffer.monitor_mode
  exit 0
end

sniffer = Catnet.new(options)
# load required files
sniffer.find_required
# iterate over protocols
sniffer.iterate_protocols
exit 0