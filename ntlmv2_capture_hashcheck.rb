#!/usr/bin/env ruby
#
# Author: Matt "scriptjunkie" Weeks, root9B
# License: GPLv2
#
# This script tests a single hash or file of hashes against an ntlmv2 
# challenge/response e.g. from auxiliary/server/capture/smb
#
# The idea is that you can identify re-used passwords between accounts
# that you do have the hash for and accounts that you do not have the
# hash for, offline and without cracking the password hashes. This saves 
# you from trying your hashes against other accounts live, which
# triggers lockouts and alerts.
#
# To use, place in the tools/ directory of a Metasploit installation,
# as it relies upon the Metasploit libraries, and run from there.
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'fastlib'
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']
require 'rex'

def usage
  $stderr.puts("\n" + "    Usage: #{$0} <options>\n" + $args.usage)
  exit
end

userprovidedname = userprovideddomain = userprovidedclichall = userprovidedhash = nil
serverchall = singlehash = hashfile = nil
verbose = false

$args = Rex::Parser::Arguments.new(
  "-a" => [ true,  "The account name from the capture" ],
  "-d" => [ true,  "The account domain from the capture" ],
  "-c" => [ true,  "The client challenge (NT_CLIENT_CHALLENGE)" ],
  "-s" => [ true,  "The server challenge (default value 1122334455667788)" ],
  "-n" => [ true,  "The NTHASH response from the client" ],
  "-t" => [ true,  "The single hash to test against the challenge/response" ],
  "-f" => [ true,  "A file of hashes to test against the challenge/response" ],
  "-v" => [ false,  "Verbose output" ],
  "-h" => [ false, "Display this help information" ])


$args.parse(ARGV) { |opt, idx, val|
  case opt
    when "-a"
      userprovidedname = val
    when "-d"
      userprovideddomain = val
    when "-c"
      userprovidedclichall = val
    when "-s"
      serverchall = val
    when "-n"
      userprovidedhash = val
    when "-t"
      singlehash = val
    when "-f"
      hashfile = val
	when "-v"
	  verbose = true
    when "-h"
      usage
    else
      usage
  end
}

if (not (userprovidedname and userprovideddomain and userprovidedclichall and userprovidedhash))
  usage
end

if (not serverchall)
  serverchall = ["1122334455667788"].pack("H*")
else
  if not serverchall =~ /^([a-fA-F0-9]{16})$/
    $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
    exit
  else
    serverchall = [serverchall].pack("H*")
  end
end

userhashcompact = [userprovidedhash].pack('H*')
clichall = [userprovidedclichall].pack('H*')

def checkHash(currenthash, userprovidedname, userprovideddomain, clichall, userhashcompact, serverchall)
	hash = [currenthash].pack('H*')
	ntlm2hash = ::Rex::Proto::NTLM::Crypt.ntlmv2_hash(userprovidedname, hash, userprovideddomain, {:pass_is_hash => true})
	capturedhash = ::Rex::Proto::NTLM::Crypt.ntlmv2_response({:challenge => serverchall, :ntlmv2_hash => ntlm2hash}, {:nt_client_challenge => clichall})[0..15]
	if capturedhash == userhashcompact
		puts "FOUND MATCH! Hash for #{userprovideddomain}\\#{userprovidedname} is #{currenthash}"
		exit
	end
end

if singlehash
	$stderr.puts "Testing #{singlehash}" if verbose
	checkHash(singlehash, userprovidedname, userprovideddomain, clichall, userhashcompact, serverchall)
elsif hashfile
	File.open(hashfile, "r") do |file_handle|
		file_handle.each_line do |hashline|
			hashline.chomp!
			# Raw hashes
			if hashline =~ /^([a-fA-F0-9]{32})$/
				$stderr.puts "Testing #{hashline}" if verbose
				checkHash(hashline, userprovidedname, userprovideddomain, clichall, userhashcompact, serverchall)
			else
				#pwdump
				matchdata = /^[^:]*:[^:]*:[^:]*:([a-fA-F0-9]{32}):[^:]*:[^:]*:/.match(hashline)
				if matchdata
					hash = matchdata[1]
					$stderr.puts "Testing #{hash}" if verbose
					checkHash(hash, userprovidedname, userprovideddomain, clichall, userhashcompact, serverchall)
				else
					$stderr.puts "Invalid line in hash file: #{hashline} " if verbose
				end
			end
		end
	end
else
	usage
end
