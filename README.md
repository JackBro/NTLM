# NTLM
Open-source script from root9B for manipulating NTLM authentication

### Author
Matt "scriptjunkie" Weeks

### License
GPLv2

## ntlmv2_capture_hashcheck.rb
This script tests a single hash or file of hashes against an ntlmv2 challenge/response e.g. from auxiliary/server/capture/smb

The idea is that you can identify re-used passwords between accounts that you do have the hash for and accounts that you do not have the hash for, offline and without cracking the password hashes. This saves you from trying your hashes against other accounts live, which triggers lockouts and alerts.

To use, place in the tools/ directory of a Metasploit installation, as it relies upon the Metasploit libraries, and run from there.

### Usage
    ruby ntlmv2_capture_hashcheck.rb -a username -d domainname -c 0101...00 -n 73332a...5113 -f /tmp/hashes.txt
