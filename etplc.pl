#!/usr/bin/perl

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact: rmkml@yahoo.fr

# Todo: remove $tutu ;)

# changelog:
# 19nov2017: new filter -y on cmd line for specific one or more years based on new ET metadata (thx)
# 18nov2017: enhance http user-agent for reducing regex + add terminal color (not on syslog)
# 13jul2016: added syslog header for TMG/ForeFront parser
# 12jul2016: fix sending to syslog
#  5nov2015: fix pcre http User-Agent
# 25jul2015: fix pcre http header ()
#  9jul2015: major rewrite and add uri depth/offset signature parser
# 30jun2015: remove legacy code
# 10jun2015: again enhance BlueCoat parser format
# 30may2015: enhance BlueCoat parser format, thx Bernie
# 27apr2015: add WebSense logs parser
# 13apr2015: first urilen implementation
# 12apr2015: fix old etplc perl print thread bug (added lock)
#  6mar2015: enhance BlueCoat parser format
# 23fev2015: rewrite to split http host and http uri for better performance
# 18fev2015: added IIS logs parser, thx Tecko
#  9jan2015: fix apache format logs, thx Alexandre
#  6jan2015: use new Sys::Hostname perl module
#  5jan2015: rewrite argument with Getopt::Long
#  3jan2015: Happy New Year and remove length minor performance
# 28dec2014: add remote_ip bluecoat main format logs v6.5.5
# 27dec2014: fix bluecoat main format logs v6.5.5, thx Damien
# 17dec2014: fix apache logs
#  5dec2014: fix apache logs, thx Eric!
# 16nov2014: add initial Remote IP option
# 15oct2014: enhance debug
#  7oct2014: modify x.lower() - synchro python
#  6oct2014: enhance cookie
#  2oct2014: add search referer content optimization
#  1oct2014: add short testing for performance on Referer and User-Agent: -
# 13sep2014: add optimization on two or more content with distance without pcre
#  9aug2014: fix CR LF injection
# 29jul2014: enhance virtual syslog over socket
# 24jul2014: enhance pcre Squid (thx @tikums) and back URI::Escape::XS
# 14jul2014: remove URI::Escape::XS
# 21jun2014: added Proxy McAfee WebGateway v7.2.x logs
#  6may2014: replace uri_unescape to decodeURIComponent on URI::Escape::XS
#  5may2014: fix $syslogsock without -s cmd line option
# 27apr2014: replace URI::Escape to URI::Escape::XS
# 30mar2014: fix cookie bug
# 26fev2014: add http response code and rewrite bluecoat parsing
# 13fev2014: new -c cmd line option (category)
# 17jan2014: new -d cmd line option (debug)
# 31dec2013: added gzip signatures support
# 21nov2013: rewrite http_cookie
#  9nov2013: added fast_pattern
#  2nov2013: rewrite with hash
# 16Oct2013: print server_hostname_ip + client_hostname_ip + client_username
# 12Oct2013: rewrite for https/ssl-tunnel and bluecoat
# 24Sep2013: change fork to perl threads queue
#  2Sep2013: add @argv -s syslog like + usage + cpuinfo + adding new fast_pattern
#  1Sep2013: rewrite User-Agent
# 25Aug2013: rewrite for referer
# 24Aug2013: rewrite for case sensitive
#  6Aug2013: add ^

use strict;
use warnings;

# for "syslog" like
use IO::Socket::INET;

# sudo aptitude install liburi-escape-xs-perl # ubuntu
# sudo yum install perl-URI-Escape-XS # fedora
use URI::Escape::XS; # decodeURIComponent()

# sudo aptitude install libstring-escape-perl # ubuntu
# sudo aptitude install liburi-perl # ubuntu
# sudo yum install perl-String-Escape # fedora
use String::Escape qw( printable unprintable );

# sudo yum install perl-Thread-Queue # fedora
use threads;
use Thread::Queue;

# on ubuntu, need manualy install since http://search.cpan.org/CPAN/authors/id/N/NW/NWCLARK/PerlIO-gzip-0.18.tar.gz and package zlib1g-dev
# sudo yum install perl-PerlIO-gzip # fedora
use PerlIO::gzip;

use Getopt::Long;

use Sys::Hostname;
my $host = hostname;

use Term::ANSIColor;

####################################################################################################

my $recieved_data;

my ($timestamp_central,$server_hostname_ip,$timestamp_unix,$client_hostname_ip,$client_username,$http_reply_code,$client_http_method,$client_http_uri,$web_hostname_ip,$client_http_useragent,$client_http_referer,$client_http_cookie,$server_remote_ip,$client_http_host,);

my $output_escape;
my @tableauuricontent;
my @tableauuseragent;
my @tableauhttpmethod;
my %hash;
my $etmsg;
my $clef;
my $clef2;

# A new empty queue
my $queue = Thread::Queue->new();

# flush after every write
$| = 1;

####################################################################################################

my $file;
my @fileemergingthreats;
my $syslog;
my $debug;
my $debug1=0;
my $debug2=0;
my $syslogsock;
my $syslogip="127.0.0.1";
my $syslogport="514";
my $syslogproto="udp";
my $category='\S+';
my $year1;
my @year2;
GetOptions ("f=s"      => \$file,    # string
            "d"        => \$debug,   # flag
            "s"        => \$syslog,  # flag
            "c=s"      => \$category,# string
            "y=s"      => \$year1)    # string
or die("Error in command line arguments\n");

if( $file )
{
  if( $file =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $file or die $!; }
  else { open FILEEMERGINGTHREATS, $file or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
}
else
{
 print "==================================================\n";
 print "ETPLC (Emerging Threats Proxy Logs Checker)\n";
 print "Check your Proxy or WebServer Logs with Emerging Threats Community Ruleset.\n";
 print "http://etplc.org - Twitter: \@Rmkml\n";
 print "\n";
 print "Example: tail -f /var/log/messages | perl etplc.pl -f abc.rules.gz\n";
 print "For enable optional syslog, add -s on command line\n";
 print "For enable optional debugging, add -d on command line\n";
 print "For enable optional category, add -c all|proxy|webserver on command line\n";
 print "For enable optional one or more years, add -y 2017,2016 on command line\n";
 print "==================================================\n";
 exit;
}

$debug1=1 && $debug2=1 if $debug;

if( $syslog )
{
 $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
}

$category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $category =~ /^webserver$/i;
$category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)' if $category =~ /^proxy$/i;

if( $year1 && $year1 =~ /^(?:([12]0\d\d)\,?)+$/ && (@year2 = $year1 =~ /([12]0\d\d)\,?/g) )
{
 if( $debug )
 {
  print "cmd line year: $_\n" foreach( @year2);
 }
}
elsif( $year1 )
{
 print "Error in command line arguments, one or more year are wrong: $year1\n";
 exit;
}

####################################################################################################

my $max_procs=0;
if( open(CPUINFO, "/proc/cpuinfo") && !$debug1)
{
 foreach( <CPUINFO> )
 {
  if( /^processor\s+\:\s\d+$/ )
  {
   $max_procs++;
  }
 }
}
else
{
 $max_procs=1;
}
close CPUINFO;

####################################################################################################

 my $urilen1='\s*urilen\:\s*(\d*\s*\<?\s*\>?\s*\d+)\;';
 my $flowbits1='\s*flowbits\:.*?\;';
 my $flow1='flow\:\s*(?:to_server|to_client|from_client|from_server)?(?:\s*\,)?(?:established)?(?:\s*\,\s*)?(?:to_server|to_client|from_client|from_server)?\;';
 my $httpmethod='\s*content\:\"([gG][eE][tT]|[pP][oO][sS][tT]|[hH][eE][aA][dD]|[sS][eE][aA][rR][cC][hH]|[pP][rR][oO][pP][fF][iI][nN][dD]|[tT][rR][aA][cC][eE]|[oO][pP][tT][iI][oO][nN][sS]|[dD][eE][bB][uU][gG]|[cC][oO][nN][nN][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[pP][uU][tT])\s*[^\"]*?\"\;(?:\s*(nocase)\;\s*|\s*http_method\;\s*|\s*depth\:\d+\;\s*)*';
 my $contentoptions1='\s*(fast_pattern)(?:\:only|\:\d+\,\d+)?\;|\s*(nocase)\;|\s*offset\:(\d+)\;|\s*depth\:(\d+)\;|\s*distance\:\s*\-?(\d+)\;|\s*within\:(\d+)\;|\s*http_raw_uri\;';
 my $negateuricontent1='\s*(?:uri)?content\:\!\"[^\"]*?\"\s*\;(?:\s*fast_pattern(?:\:only|\d+\,\d+)?\;|\s*nocase\;|\s*http_uri\;|\s*http_header\;|\s*http_cookie\;|\s*offset\:\d+\;|\s*depth\:\d+\;|\s*http_raw_uri\;|\s*distance\:\s*\-?\d+\;|\s*within\:\d+\;|\s*http_client_body\;)*';
 my $extracontentoptions='\s*threshold\:.*?\;|\s*flowbits\:.*?\;|\s*isdataat\:\d+(?:\,relative)?\;|\s*dsize\:[\<\>]*\d+\;|\s*detection_filter\:.*?\;|\s*priority\:\d+\;|\s*metadata\:.*?\;';
 #my $referencesidrev='(?:\s*reference\:.*?\;\s*)*\s*classtype\:.*?\;\s*sid\:\d+\;\s*rev\:\d+\;\s*\)\s*';
 my $referencesidrev='(?:\s*reference\:.*?\;\s*)*\s*classtype\:.*?\;\s*sid\:\d+\;\s*rev\:\d+\;';
 my $pcreuri='\s*pcre\:\"\/(.*?)\/[smiUGDIR]*\"\;'; # not header/Cookie/Post_payload!
 my $pcreagent='\s*pcre\:\"\/(.*?)\/[smiH]*\"\;';
 my $pcrecookie='\s*pcre\:\"\/(.*?)\/[smiC]*\"\;';
 my $createdat='\bcreated_at\s(\d\d\d\d)';

foreach $_ ( @fileemergingthreats )
{
 chomp($_);
 #print "brut: $_\n" if $debug1;
 if($_=~/^(?:\#|$)/)
 {
  next;
 }

#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_CLIENT Possible Adobe Reader and Acrobat Forms Data Format Remote Security Bypass Attempt"; flow:established,to_client; file_data; content:"%FDF-"; depth:300; content:"/F(JavaScript|3a|"; nocase; distance:0; reference:url,www.securityfocus.com/bid/37763; reference:cve,2009-3956; reference:url,doc.emergingthreats.net/2010664; reference:url,www.stratsec.net/files/SS-2010-001_Stratsec_Acrobat_Script_Injection_Security_Advisory_v1.0.pdf; classtype:attempted-user; sid:2010664; rev:8;)
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+\S+\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*flow\:\s*(?:to_client\s*\,|from_server\s*\,)?established(?:\s*\,\s*to_client|\s*\,\s*from_server)?\;/ )
 {
  #print "to_client: $_\n" if $debug1;
  next;
 }

#alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Overtoolbar.net Backdoor ICMP Checkin Request"; dsize:9; icode:0; itype:8; content:"Echo This"; reference:url,doc.emergingthreats.net/2009130; classtype:trojan-activity; sid:2009130; rev:3;)
#alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"ET POLICY Protocol 41 IPv6 encapsulation potential 6in4 IPv6 tunnel active"; ip_proto:41; threshold:type both,track by_dst, count 1, seconds 60; reference:url,en.wikipedia.org/wiki/6in4; classtype:policy-violation; sid:2012141; rev:2;)
 #elsif( $_=~ /^\s*alert\s+(?:icmp|ip)\s+\S+\s+\S+\s+\-\>\s+\S+\s+\S+\s+/ )
 elsif( $_=~ /^\s*alert\s+icmp\s+\S+\s+\S+\s+\-\>\s+\S+\s+\S+\s+/ )
 {
  #print "icmp_ip: $_\n" if $debug1;
  next;
 }

#alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"ET POLICY ICQ Message"; flow: established; content:"|2A02|"; depth: 2; content:"|000400060000|"; offset: 6; depth: 6; reference:url,doc.emergingthreats.net/2001805; classtype:policy-violation; sid:2001805; rev:5;)
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\<\>\s+\S+\s+\S+\s+/ )
 {
  #print "udp_tcp_<_>: $_\n" if $debug1;
  next;
 }

 elsif( $_=~ /\bhttp_client_body\;/ )
 {
  next;
 }

 # begin http_uri
# elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$flowbits1)?(?:$urilen1)?(?:$httpmethod)?(?:$negateuricontent1)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*(?:http_uri|http_raw_uri)\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreuri)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreagent)?(?:$negateuricontent1)?(?:$extracontentoptions)?$referencesidrev$/ )
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$flowbits1)?(?:$urilen1)?(?:$httpmethod)?(?:$negateuricontent1)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*(?:http_uri|http_raw_uri)\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreuri)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreagent)?(?:$negateuricontent1)?(?:$extracontentoptions)?$referencesidrev[^\n]*$createdat/ )
 {
  my $http_method1=0;
  my $http_methodnocase1=0;
  my $http_urioffset=0;
  my $http_uridepth=0;
  #
  if( $debug1 ){
   print "brut1: $_\n"; print "here1: 1: $1," if $1; print " 2: $2," if $2; print " 3: $3," if $3; print " 4: $4," if $4; print " 5: $5," if $5; print " 6: $6," if $6; print " 7: $7," if $7; print " 8: $8," if $8; print " 9: $9," if $9; print " 10: $10," if $10; print " 11: $11," if $11; print " 12: $12," if $12; print " 13: $13," if $13; print " 14: $14," if $14; print " 15: $15," if $15; print " 16: $16," if $16; print " 17: $17," if $17; print " 18: $18," if $18; print " 19: $19," if $19; print " 20: $20," if $20; print " 21: $21," if $21; print " 22: $22," if $22; print " 23: $23," if $23; print " 24: $24," if $24; print " 25: $25," if $25; print " 26: $26," if $26; print " 27: $27," if $27; print " 28: $28," if $28; print " 29: $29," if $29; print " 30: $30," if $30; print " 31: $31," if $31; print " 32: $32," if $32; print " 33: $33," if $33; print " 34: $34," if $34; print " 35: $35," if $35; print " 36: $36," if $36; print " 37: $37," if $37; print " 38: $38," if $38; print " 39: $39," if $39; print " 40: $40," if $40; print " 41: $41," if $41; print " 42: $42," if $42; print " 43: $43," if $43; print " 44: $44," if $44; print " 45: $45," if $45; print " 46: $46," if $46; print " 47: $47," if $47; print " 48: $48," if $48; print " 49: $49," if $49; print " 50: $50," if $50; print " 51: $51," if $51; print " 52: $52," if $52; print " 53: $53," if $53; print " 54: $54," if $54; print " 55: $55," if $55; print " 56: $56," if $56; print " 57: $57," if $57; print " 58: $58," if $58; print " 59: $59," if $59; print " 60: $60," if $60; print " 61: $61," if $61; print " 62: $62," if $62; print " 63: $63," if $63; print " 64: $64," if $64; print " 65: $65," if $65; print " 66: $66," if $66; print " 67: $67," if $67; print " 68: $68," if $68; print " 69: $69," if $69; print " 70: $70," if $70; print " 71: $71," if $71; print " 72: $72," if $72; print " 73: $73," if $73; print " 74: $74," if $74; print " 75: $75," if $75; print " 76: $76," if $76; print " 77: $77," if $77; print " 78: $78," if $78; print " 79: $79," if $79; print " 80: $80," if $80; print " 81: $81," if $81; print " 82: $82," if $82; print " 83: $83," if $83; print " 84: $84," if $84; print " 85: $85," if $85; print " 86: $86," if $86; print " 87: $87," if $87; print " 88: $88," if $88; print " 89: $89," if $89; print " 90: $90," if $90; print " 91: $91," if $91; print " 92: $92," if $92; print " 93: $93," if $93; print " 94: $94," if $94; print " 95: $95," if $95; print " 96: $96," if $96; print " 97: $97," if $97; print " 98: $98," if $98; print " 99: $99," if $99; print " 100: $100," if $100; print " 101: $101," if $101; print " 102: $102," if $102; print " 103: $103," if $103; print " 104: $104," if $104; print " 105: $105," if $105; print " 106: $106," if $106; print " 107: $107," if $107; print " 108: $108," if $108; print " 109: $109," if $109; print " 110: $110," if $110; print " 111: $111," if $111; print " 112: $112," if $112; print " 113: $113," if $113; print " 114: $114," if $114; print " 115: $115," if $115; print " 116: $116," if $116; print " 117: $117," if $117; print " 118: $118," if $118; print " 119: $119," if $119; print " 120: $120," if $120; print " 121: $121," if $121; print " 122: $122," if $122; print " 123: $123," if $123; print " 124: $124," if $124; print " 125: $125," if $125; print " 126: $126," if $126; print " 127: $127," if $127; print " 128: $128," if $128; print " 129: $129," if $129; print " 130: $130," if $130; print " 131: $131," if $131; print " 132: $132," if $132; print " 133: $133," if $133; print " 134: $134," if $134; print " 135: $135," if $135; print " 136: $136," if $136; print " 137: $137," if $137; print " 138: $138," if $138; print " 139: $139," if $139; print " 140: $140," if $140; print " 141: $141," if $141; print " 142: $142," if $142; print " 143: $143" if $143; print " 144: $144," if $144; print " 145: $145," if $145; print " 146: $146," if $146; print " 147: $147," if $147; print " 148: $148," if $148; print " 149: $149," if $149; print " 150: $150," if $150; print " 151: $151," if $151; print " 152: $152," if $152; print " 153: $153," if $153; print " 154: $154," if $154; print " 155: $155," if $155; print " 156: $156," if $156; print " 157: $157," if $157; print " 158: $158," if $158; print " 159: $159," if $159; print " 160: $160," if $160; print " 161: $161," if $161; print " 162: $162," if $162; print " 163: $163," if $163; print " 164: $164," if $164; print " 165: $165," if $165; print " 166: $166," if $166; print " 167: $167," if $167; print " 168: $168," if $168; print " 169: $169," if $169; print " 170: $170," if $170; print " 171: $171," if $171; print " 172: $172," if $172; print " 173: $173," if $173; print " 174: $174," if $174; print " 175: $175," if $175; print " 176: $176," if $176; print " 177: $177," if $177; print " 178: $178," if $178; print " 179: $179," if $179; print " 180: $180," if $180; print " 181: $181," if $181; print " 182: $182," if $182; print " 183: $183," if $183; print " 184: $184," if $184; print " 185: $185," if $185; print " 186: $186," if $186; print " 187: $187," if $187; print " 188: $188," if $188; print " 189: $189," if $189; print " 190: $190," if $190; print " 191: $191," if $191; print " 192: $192," if $192; print " 193: $193," if $193; print " 194: $194," if $194; print " 195: $195," if $195; print " 196: $196," if $196; print " 197: $197," if $197; print " 198: $198," if $198; print " 199: $199," if $199; print " 200: $200," if $200; print " 201: $201," if $201; print " 202: $202," if $202; print " 203: $203," if $203; print " 204: $204," if $204; print " 205: $205," if $205; print "\n";
  }

  my $etmsg1=$1;
  #
  my $http_urilen1=$2 if $2;
  #
     $http_method1=$3 if $3;
     $http_methodnocase1=$4 if $4;
  #
  my $http_uri03=$5 if $5;		# old 5
  my $http_urifast5=$6 if $6;
  my $http_urinocase5=$7 if $7;
     $http_urioffset=$8 if $8;
     $http_uridepth=$9 if $9;
  # distance
  # distance
  my $http_urifast9=$12 if $12;
  my $http_urinocase10=$13 if $13;
     $http_urioffset=$14 if $14;
     $http_uridepth=$15 if $15;
  # distance
  # distance
  #
  my $http_uri08=$18 if $18;		# old 14
  my $http_urifast14=$19 if $19;
  my $http_urinocase12=$20 if $20;
  # offset/depth
  # offset/depth
  my $distance9=$23 if defined($23);		# 23
  my $distance10=$24 if defined($24);
  my $http_urifast18=$25 if $25;
  my $http_urinocase15=$26 if $26;
  # offset/depth
  # offset/depth
  my $distance11=$29 if defined($29);
  my $distance12=$30 if defined($30);
  #
  my $http_uri13=$31 if $31;		# old 23
  my $http_urifast23=$32 if $32;
  my $http_urinocase19=$33 if $33;
  # offset/depth
  # offset/depth
  my $distance14=$36 if defined($36);
  my $distance15=$37 if defined($37);
  my $http_urifast27=$38 if $38;
  my $http_urinocase22=$39 if $39;
  # offset/depth
  # offset/depth
  my $distance16=$42 if defined($42);
  my $distance17=$43 if defined($43);
  #
  my $http_uri18=$44 if $44;		# old 32
  my $http_urifast32=$45 if $45;
  my $http_urinocase26=$46 if $46;
  # offset/depth
  # offset/depth
  my $distance19=$49 if defined($49);
  my $distance20=$50 if defined($50);
  my $http_urifast36=$51 if $51;
  my $http_urinocase29=$52 if $52;
  # offset/depth
  # offset/depth
  my $distance21=$55 if defined($55);
  my $distance22=$56 if defined($56);
  #
  my $http_uri23=$57 if $57;		# old 41
  my $http_urifast41=$58 if $58;
  my $http_urinocase33=$59 if $59;
  # offset/depth
  # offset/depth
  my $distance24=$62 if defined($62);
  my $distance25=$63 if defined($63);
  my $http_urifast44=$64 if $64;
  my $http_urinocase36=$65 if $65;
  # offset/depth
  # offset/depth
  my $distance26=$68 if defined($68);
  my $distance27=$69 if defined($69);
  #
  my $http_uri28=$70 if $70;		# old 50
  my $http_urifast49=$71 if $71;
  my $http_urinocase40=$72 if $72;
  # offset/depth
  # offset/depth
  my $distance29=$75 if defined($75);
  my $distance30=$76 if defined($76);
  my $http_urifast54=$77 if $77;
  my $http_urinocase43=$78 if $78;
  # offset/depth
  # offset/depth
  my $distance31=$81 if defined($81);
  my $distance32=$82 if defined($82);
  #
  my $http_uri33=$83 if $83;		# old 59
  my $http_urifast58=$84 if $84;
  my $http_urinocase47=$85 if $85;
  # offset/depth
  # offset/depth
  my $distance34=$88 if defined($88);
  my $distance35=$89 if defined($89);
  my $http_urifast62=$90 if $90;
  my $http_urinocase50=$91 if $91;
  # offset/depth
  # offset/depth
  my $distance36=$94 if defined($94);
  my $distance37=$95 if defined($95);
  #
  my $http_uri38=$96 if $96;		# old 68
  # fastpattern
  my $http_urinocase54=$98 if $98;
  # offset/depth
  # offset/depth
  # distance
  # distance
  # fastpattern
  my $http_urinocase57=$104 if $104;
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $http_uri43=$109 if $109;		# old 61
  # fastpattern
  my $http_urinocase61=$111 if $111;
  # offset/depth
  # offset/depth
  # distance
  # distance
  # fastpattern
  my $http_urinocase64=$117 if $117;
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $http_uri48=$122 if $122;		# old 68
  # fastpattern
  my $http_urinocase68=$124 if $124;
  # offset/depth
  # offset/depth
  # distance
  # distance
  # fastpattern
  my $http_urinocase71=$130 if $130;
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $http_uri53=$135 if $135;		# old 75
  # fastpattern
  my $http_urinocase75=$137 if $137;
  # offset/depth
  # offset/depth
  # distance
  # distance
  # fastpattern
  my $http_urinocase78=$143 if $143;
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $http_uri58=$148 if $148;		# old 82
  # fastpattern
  my $http_urinocase82=$150 if $150;
  # offset/depth
  # offset/depth
  # distance
  # distance
  # fastpattern
  my $http_urinocase85=$156 if $156;
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $http_uri63=$161 if $161;		# old 89
  # fastpattern
  my $http_urinocase89=$163 if $163;
  # offset/depth
  # offset/depth
  # distance
  # distance
  # fastpattern
  my $http_urinocase92=$169 if $169;
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $http_header68=$174 if $174;	# old 96
  # fastpattern
  my $http_headernocase96=$176 if $176;
  # offset/depth
  # offset/depth
  # distance
  # distance
  # fastpattern
  my $http_headernocase99=$182 if $182;
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $pcre_uri73=$187 if $187;		# old 131
  #
  my $http_header121=$188 if $188;      # old 132
  my $http_headerfast122=$189 if $189;
  my $http_headernocase123=$190 if $190;
  # offset/depth
  # offset/depth
  my $distance124=$193 if defined($193);
  my $distance125=$194 if defined($194);
  my $http_headerfast126=$195 if $195;
  my $http_headernocase127=$196 if $196;
  # offset/depth
  # offset/depth
  my $distance128=$199 if defined($199);
  my $distance129=$200 if defined($200);
  #
  my $pcre_agent79=$201 if $201;	# old 141
  my $metadatacreatedyear=$202 if $202;

  # check what is http_uri best length ?
  my $httpuricourt=0;
  my $http_uri03_length=0;
  my $http_uri08_length=0;
  my $http_uri13_length=0;
  my $http_uri18_length=0;
  my $http_uri23_length=0;
  my $http_uri28_length=0;
  my $http_uri33_length=0;
  my $http_uri38_length=0;
  my $http_uri43_length=0;
  my $http_uri48_length=0;
  my $http_uri53_length=0;
  my $http_uri58_length=0;
  my $http_uri63_length=0;
  $http_uri03_length=length($http_uri03) if $http_uri03;
  $http_uri08_length=length($http_uri08) if $http_uri08;
  $http_uri13_length=length($http_uri13) if $http_uri13;
  $http_uri18_length=length($http_uri18) if $http_uri18;
  $http_uri23_length=length($http_uri23) if $http_uri23;
  $http_uri28_length=length($http_uri28) if $http_uri28;
  $http_uri33_length=length($http_uri33) if $http_uri33;
  $http_uri38_length=length($http_uri38) if $http_uri38;
  $http_uri43_length=length($http_uri43) if $http_uri43;
  $http_uri48_length=length($http_uri48) if $http_uri48;
  $http_uri53_length=length($http_uri53) if $http_uri53;
  $http_uri58_length=length($http_uri58) if $http_uri58;
  $http_uri63_length=length($http_uri63) if $http_uri63;
  if( $http_uri03_length >= $http_uri08_length && $http_uri03_length >= $http_uri13_length && $http_uri03_length >= $http_uri18_length && $http_uri03_length >= $http_uri23_length && $http_uri03_length >= $http_uri28_length && $http_uri03_length >= $http_uri33_length && $http_uri03_length >= $http_uri38_length && $http_uri03_length >= $http_uri43_length && $http_uri03_length >= $http_uri48_length && $http_uri03_length >= $http_uri53_length && $http_uri03_length >= $http_uri58_length && $http_uri03_length >= $http_uri63_length)
  { $httpuricourt=$http_uri03; }
  elsif( $http_uri08_length >= $http_uri03_length && $http_uri08_length >= $http_uri13_length && $http_uri08_length >= $http_uri18_length && $http_uri08_length >= $http_uri23_length && $http_uri08_length >= $http_uri28_length && $http_uri08_length >= $http_uri33_length && $http_uri08_length >= $http_uri38_length && $http_uri08_length >= $http_uri43_length && $http_uri08_length >= $http_uri48_length && $http_uri08_length >= $http_uri53_length && $http_uri08_length >= $http_uri58_length && $http_uri08_length >= $http_uri63_length)
  { $httpuricourt=$http_uri08; $http_urioffset=0; $http_uridepth=0; }
  elsif( $http_uri13_length >= $http_uri03_length && $http_uri13_length >= $http_uri08_length && $http_uri13_length >= $http_uri18_length && $http_uri13_length >= $http_uri23_length && $http_uri13_length >= $http_uri28_length && $http_uri13_length >= $http_uri33_length && $http_uri13_length >= $http_uri38_length && $http_uri13_length >= $http_uri43_length && $http_uri13_length >= $http_uri48_length && $http_uri13_length >= $http_uri53_length && $http_uri13_length >= $http_uri58_length && $http_uri13_length >= $http_uri63_length)
  { $httpuricourt=$http_uri13; $http_urioffset=0; $http_uridepth=0; }
  elsif( $http_uri18_length >= $http_uri03_length && $http_uri18_length >= $http_uri08_length && $http_uri18_length >= $http_uri13_length && $http_uri18_length >= $http_uri23_length && $http_uri18_length >= $http_uri28_length && $http_uri18_length >= $http_uri33_length && $http_uri18_length >= $http_uri38_length && $http_uri18_length >= $http_uri43_length && $http_uri18_length >= $http_uri48_length && $http_uri18_length >= $http_uri53_length && $http_uri18_length >= $http_uri58_length && $http_uri18_length >= $http_uri63_length)
  { $httpuricourt=$http_uri18; $http_urioffset=0; $http_uridepth=0; }
  elsif( $http_uri23_length >= $http_uri03_length && $http_uri23_length >= $http_uri08_length && $http_uri23_length >= $http_uri13_length && $http_uri23_length >= $http_uri18_length && $http_uri23_length >= $http_uri28_length && $http_uri23_length >= $http_uri33_length && $http_uri23_length >= $http_uri38_length && $http_uri23_length >= $http_uri43_length && $http_uri23_length >= $http_uri48_length && $http_uri23_length >= $http_uri53_length && $http_uri23_length >= $http_uri58_length && $http_uri23_length >= $http_uri63_length)
  { $httpuricourt=$http_uri23; $http_urioffset=0; $http_uridepth=0; }
  elsif( $http_uri28_length >= $http_uri03_length && $http_uri28_length >= $http_uri08_length && $http_uri28_length >= $http_uri13_length && $http_uri28_length >= $http_uri18_length && $http_uri28_length >= $http_uri23_length && $http_uri28_length >= $http_uri33_length && $http_uri28_length >= $http_uri38_length && $http_uri28_length >= $http_uri43_length && $http_uri28_length >= $http_uri48_length && $http_uri28_length >= $http_uri53_length && $http_uri28_length >= $http_uri58_length && $http_uri28_length >= $http_uri63_length)
  { $httpuricourt=$http_uri28; $http_urioffset=0; $http_uridepth=0; }
  elsif( $http_uri33_length >= $http_uri03_length && $http_uri33_length >= $http_uri08_length && $http_uri33_length >= $http_uri13_length && $http_uri33_length >= $http_uri18_length && $http_uri33_length >= $http_uri23_length && $http_uri33_length >= $http_uri28_length && $http_uri33_length >= $http_uri38_length && $http_uri33_length >= $http_uri43_length && $http_uri33_length >= $http_uri48_length && $http_uri33_length >= $http_uri53_length && $http_uri33_length >= $http_uri58_length && $http_uri33_length >= $http_uri63_length)
  { $httpuricourt=$http_uri33; $http_urioffset=0; $http_uridepth=0; }
  elsif( $http_uri38_length >= $http_uri03_length && $http_uri38_length >= $http_uri08_length && $http_uri38_length >= $http_uri13_length && $http_uri38_length >= $http_uri18_length && $http_uri38_length >= $http_uri23_length && $http_uri38_length >= $http_uri28_length && $http_uri38_length >= $http_uri33_length && $http_uri38_length >= $http_uri43_length && $http_uri38_length >= $http_uri48_length && $http_uri38_length >= $http_uri53_length && $http_uri38_length >= $http_uri58_length && $http_uri38_length >= $http_uri63_length)
  { $httpuricourt=$http_uri38; $http_urioffset=0; $http_uridepth=0; }
  elsif( $http_uri43_length >= $http_uri03_length && $http_uri43_length >= $http_uri08_length && $http_uri43_length >= $http_uri13_length && $http_uri43_length >= $http_uri18_length && $http_uri43_length >= $http_uri23_length && $http_uri43_length >= $http_uri28_length && $http_uri43_length >= $http_uri33_length && $http_uri43_length >= $http_uri38_length && $http_uri43_length >= $http_uri48_length && $http_uri43_length >= $http_uri53_length && $http_uri43_length >= $http_uri58_length && $http_uri43_length >= $http_uri63_length)
  { $httpuricourt=$http_uri43; $http_urioffset=0; $http_uridepth=0; }
  elsif( $http_uri48_length >= $http_uri03_length && $http_uri48_length >= $http_uri08_length && $http_uri48_length >= $http_uri13_length && $http_uri48_length >= $http_uri18_length && $http_uri48_length >= $http_uri23_length && $http_uri48_length >= $http_uri28_length && $http_uri48_length >= $http_uri33_length && $http_uri48_length >= $http_uri38_length && $http_uri48_length >= $http_uri43_length && $http_uri48_length >= $http_uri53_length && $http_uri48_length >= $http_uri58_length && $http_uri48_length >= $http_uri63_length)
  { $httpuricourt=$http_uri48; $http_urioffset=0; $http_uridepth=0; }
  elsif( $http_uri53_length >= $http_uri03_length && $http_uri53_length >= $http_uri08_length && $http_uri53_length >= $http_uri13_length && $http_uri53_length >= $http_uri18_length && $http_uri53_length >= $http_uri23_length && $http_uri53_length >= $http_uri28_length && $http_uri53_length >= $http_uri33_length && $http_uri53_length >= $http_uri38_length && $http_uri53_length >= $http_uri43_length && $http_uri53_length >= $http_uri48_length && $http_uri53_length >= $http_uri58_length && $http_uri53_length >= $http_uri63_length)
  { $httpuricourt=$http_uri53; $http_urioffset=0; $http_uridepth=0; }
  elsif( $http_uri58_length >= $http_uri03_length && $http_uri58_length >= $http_uri08_length && $http_uri58_length >= $http_uri13_length && $http_uri58_length >= $http_uri18_length && $http_uri58_length >= $http_uri23_length && $http_uri58_length >= $http_uri28_length && $http_uri58_length >= $http_uri33_length && $http_uri58_length >= $http_uri38_length && $http_uri58_length >= $http_uri43_length && $http_uri58_length >= $http_uri48_length && $http_uri58_length >= $http_uri53_length && $http_uri58_length >= $http_uri63_length)
  { $httpuricourt=$http_uri58; $http_urioffset=0; $http_uridepth=0; }
  elsif( $http_uri63_length >= $http_uri03_length && $http_uri63_length >= $http_uri08_length && $http_uri63_length >= $http_uri13_length && $http_uri63_length >= $http_uri18_length && $http_uri63_length >= $http_uri23_length && $http_uri63_length >= $http_uri28_length && $http_uri63_length >= $http_uri33_length && $http_uri63_length >= $http_uri38_length && $http_uri63_length >= $http_uri43_length && $http_uri63_length >= $http_uri48_length && $http_uri63_length >= $http_uri53_length && $http_uri63_length >= $http_uri58_length)
  { $httpuricourt=$http_uri63; $http_urioffset=0; $http_uridepth=0; }

  # need escape special char before compare with pcre
  $http_uri03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri03 && $pcre_uri73; # (
  $http_uri03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri03 && $pcre_uri73; # )
  $http_uri03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri03 && $pcre_uri73; # *
  $http_uri03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri03 && $pcre_uri73; # +
  $http_uri03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri03 && $pcre_uri73; # -
  $http_uri03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri03 && $pcre_uri73; # .
  $http_uri03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri03 && $pcre_uri73; # /
  $http_uri03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri03 && $pcre_uri73; # ?
  $http_uri03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri03 && $pcre_uri73; # [
  $http_uri03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri03 && $pcre_uri73; # ]
  $http_uri03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri03 && $pcre_uri73; # ^
  $http_uri03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri03 && $pcre_uri73; # {
  $http_uri03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri03 && $pcre_uri73; # }
  $http_uri08 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri08 && $pcre_uri73; # (
  $http_uri08 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri08 && $pcre_uri73; # )
  $http_uri08 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri08 && $pcre_uri73; # *
  $http_uri08 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri08 && $pcre_uri73; # +
  $http_uri08 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri08 && $pcre_uri73; # -
  $http_uri08 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri08 && $pcre_uri73; # .
  $http_uri08 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri08 && $pcre_uri73; # /
  $http_uri08 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri08 && $pcre_uri73; # ?
  $http_uri08 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri08 && $pcre_uri73; # [
  $http_uri08 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri08 && $pcre_uri73; # ]
  $http_uri08 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri08 && $pcre_uri73; # ^
  $http_uri08 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri08 && $pcre_uri73; # {
  $http_uri08 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri08 && $pcre_uri73; # }
  $http_uri13 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri13 && $pcre_uri73; # (
  $http_uri13 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri13 && $pcre_uri73; # )
  $http_uri13 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri13 && $pcre_uri73; # *
  $http_uri13 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri13 && $pcre_uri73; # +
  $http_uri13 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri13 && $pcre_uri73; # -
  $http_uri13 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri13 && $pcre_uri73; # .
  $http_uri13 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri13 && $pcre_uri73; # /
  $http_uri13 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri13 && $pcre_uri73; # ?
  $http_uri13 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri13 && $pcre_uri73; # [
  $http_uri13 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri13 && $pcre_uri73; # ]
  $http_uri13 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri13 && $pcre_uri73; # ^
  $http_uri13 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri13 && $pcre_uri73; # {
  $http_uri13 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri13 && $pcre_uri73; # }
  $http_uri18 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri18 && $pcre_uri73; # (
  $http_uri18 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri18 && $pcre_uri73; # )
  $http_uri18 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri18 && $pcre_uri73; # *
  $http_uri18 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri18 && $pcre_uri73; # +
  $http_uri18 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri18 && $pcre_uri73; # -
  $http_uri18 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri18 && $pcre_uri73; # .
  $http_uri18 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri18 && $pcre_uri73; # /
  $http_uri18 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri18 && $pcre_uri73; # ?
  $http_uri18 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri18 && $pcre_uri73; # [
  $http_uri18 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri18 && $pcre_uri73; # ]
  $http_uri18 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri18 && $pcre_uri73; # ^
  $http_uri18 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri18 && $pcre_uri73; # {
  $http_uri18 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri18 && $pcre_uri73; # }
  $http_uri23 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri23 && $pcre_uri73; # (
  $http_uri23 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri23 && $pcre_uri73; # )
  $http_uri23 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri23 && $pcre_uri73; # *
  $http_uri23 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri23 && $pcre_uri73; # +
  $http_uri23 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri23 && $pcre_uri73; # -
  $http_uri23 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri23 && $pcre_uri73; # .
  $http_uri23 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri23 && $pcre_uri73; # /
  $http_uri23 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri23 && $pcre_uri73; # ?
  $http_uri23 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri23 && $pcre_uri73; # [
  $http_uri23 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri23 && $pcre_uri73; # ]
  $http_uri23 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri23 && $pcre_uri73; # ^
  $http_uri23 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri23 && $pcre_uri73; # {
  $http_uri23 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri23 && $pcre_uri73; # }
  $http_uri28 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri28 && $pcre_uri73; # (
  $http_uri28 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri28 && $pcre_uri73; # )
  $http_uri28 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri28 && $pcre_uri73; # *
  $http_uri28 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri28 && $pcre_uri73; # +
  $http_uri28 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri28 && $pcre_uri73; # -
  $http_uri28 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri28 && $pcre_uri73; # .
  $http_uri28 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri28 && $pcre_uri73; # /
  $http_uri28 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri28 && $pcre_uri73; # ?
  $http_uri28 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri28 && $pcre_uri73; # [
  $http_uri28 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri28 && $pcre_uri73; # ]
  $http_uri28 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri28 && $pcre_uri73; # ^
  $http_uri28 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri28 && $pcre_uri73; # {
  $http_uri28 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri28 && $pcre_uri73; # }
  $http_uri33 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri33 && $pcre_uri73; # (
  $http_uri33 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri33 && $pcre_uri73; # )
  $http_uri33 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri33 && $pcre_uri73; # *
  $http_uri33 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri33 && $pcre_uri73; # +
  $http_uri33 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri33 && $pcre_uri73; # -
  $http_uri33 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri33 && $pcre_uri73; # .
  $http_uri33 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri33 && $pcre_uri73; # /
  $http_uri33 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri33 && $pcre_uri73; # ?
  $http_uri33 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri33 && $pcre_uri73; # [
  $http_uri33 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri33 && $pcre_uri73; # ]
  $http_uri33 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri33 && $pcre_uri73; # ^
  $http_uri33 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri33 && $pcre_uri73; # {
  $http_uri33 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri33 && $pcre_uri73; # }
  $http_uri38 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri38 && $pcre_uri73; # (
  $http_uri38 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri38 && $pcre_uri73; # )
  $http_uri38 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri38 && $pcre_uri73; # *
  $http_uri38 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri38 && $pcre_uri73; # +
  $http_uri38 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri38 && $pcre_uri73; # -
  $http_uri38 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri38 && $pcre_uri73; # .
  $http_uri38 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri38 && $pcre_uri73; # /
  $http_uri38 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri38 && $pcre_uri73; # ?
  $http_uri38 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri38 && $pcre_uri73; # [
  $http_uri38 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri38 && $pcre_uri73; # ]
  $http_uri38 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri38 && $pcre_uri73; # ^
  $http_uri38 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri38 && $pcre_uri73; # {
  $http_uri38 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri38 && $pcre_uri73; # }
  $http_uri43 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri43 && $pcre_uri73; # (
  $http_uri43 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri43 && $pcre_uri73; # )
  $http_uri43 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri43 && $pcre_uri73; # *
  $http_uri43 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri43 && $pcre_uri73; # +
  $http_uri43 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri43 && $pcre_uri73; # -
  $http_uri43 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri43 && $pcre_uri73; # .
  $http_uri43 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri43 && $pcre_uri73; # /
  $http_uri43 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri43 && $pcre_uri73; # ?
  $http_uri43 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri43 && $pcre_uri73; # [
  $http_uri43 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri43 && $pcre_uri73; # ]
  $http_uri43 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri43 && $pcre_uri73; # ^
  $http_uri43 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri43 && $pcre_uri73; # {
  $http_uri43 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri43 && $pcre_uri73; # }
  $http_uri48 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri48 && $pcre_uri73; # (
  $http_uri48 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri48 && $pcre_uri73; # )
  $http_uri48 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri48 && $pcre_uri73; # *
  $http_uri48 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri48 && $pcre_uri73; # +
  $http_uri48 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri48 && $pcre_uri73; # -
  $http_uri48 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri48 && $pcre_uri73; # .
  $http_uri48 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri48 && $pcre_uri73; # /
  $http_uri48 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri48 && $pcre_uri73; # ?
  $http_uri48 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri48 && $pcre_uri73; # [
  $http_uri48 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri48 && $pcre_uri73; # ]
  $http_uri48 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri48 && $pcre_uri73; # ^
  $http_uri48 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri48 && $pcre_uri73; # {
  $http_uri48 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri48 && $pcre_uri73; # }
  $http_uri53 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri53 && $pcre_uri73; # (
  $http_uri53 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri53 && $pcre_uri73; # )
  $http_uri53 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri53 && $pcre_uri73; # *
  $http_uri53 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri53 && $pcre_uri73; # +
  $http_uri53 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri53 && $pcre_uri73; # -
  $http_uri53 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri53 && $pcre_uri73; # .
  $http_uri53 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri53 && $pcre_uri73; # /
  $http_uri53 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri53 && $pcre_uri73; # ?
  $http_uri53 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri53 && $pcre_uri73; # [
  $http_uri53 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri53 && $pcre_uri73; # ]
  $http_uri53 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri53 && $pcre_uri73; # ^
  $http_uri53 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri53 && $pcre_uri73; # {
  $http_uri53 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri53 && $pcre_uri73; # }
  $http_uri58 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri58 && $pcre_uri73; # (
  $http_uri58 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri58 && $pcre_uri73; # )
  $http_uri58 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri58 && $pcre_uri73; # *
  $http_uri58 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri58 && $pcre_uri73; # +
  $http_uri58 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri58 && $pcre_uri73; # -
  $http_uri58 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri58 && $pcre_uri73; # .
  $http_uri58 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri58 && $pcre_uri73; # /
  $http_uri58 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri58 && $pcre_uri73; # ?
  $http_uri58 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri58 && $pcre_uri73; # [
  $http_uri58 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri58 && $pcre_uri73; # ]
  $http_uri58 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri58 && $pcre_uri73; # ^
  $http_uri58 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri58 && $pcre_uri73; # {
  $http_uri58 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri58 && $pcre_uri73; # }
  $http_uri63 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri63 && $pcre_uri73; # (
  $http_uri63 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri63 && $pcre_uri73; # )
  $http_uri63 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri63 && $pcre_uri73; # *
  $http_uri63 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri63 && $pcre_uri73; # +
  $http_uri63 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri63 && $pcre_uri73; # -
  $http_uri63 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri63 && $pcre_uri73; # .
  $http_uri63 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri63 && $pcre_uri73; # /
  $http_uri63 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri63 && $pcre_uri73; # ?
  $http_uri63 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri63 && $pcre_uri73; # [
  $http_uri63 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri63 && $pcre_uri73; # ]
  $http_uri63 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri63 && $pcre_uri73; # ^
  $http_uri63 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri63 && $pcre_uri73; # {
  $http_uri63 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri63 && $pcre_uri73; # }
  $http_header68 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header68 && $pcre_agent79; # (
  $http_header68 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header68 && $pcre_agent79; # )
  $http_header68 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header68 && $pcre_agent79; # *
  $http_header68 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header68 && $pcre_agent79; # +
  $http_header68 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header68 && $pcre_agent79; # -
  $http_header68 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header68 && $pcre_agent79; # .
  $http_header68 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header68 && $pcre_agent79; # /
  $http_header68 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header68 && $pcre_agent79; # ?
  $http_header68 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header68 && $pcre_agent79; # [
  $http_header68 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header68 && $pcre_agent79; # ]
  #$http_header68 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header68 && $pcre_agent79; # ^
  $http_header68 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header68 && $pcre_agent79; # {
  $http_header68 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header68 && $pcre_agent79; # }
  $http_header121 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header121 && $pcre_agent79; # (
  $http_header121 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header121 && $pcre_agent79; # )
  $http_header121 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header121 && $pcre_agent79; # *
  $http_header121 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header121 && $pcre_agent79; # +
  $http_header121 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header121 && $pcre_agent79; # -
  $http_header121 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header121 && $pcre_agent79; # .
  $http_header121 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header121 && $pcre_agent79; # /
  $http_header121 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header121 && $pcre_agent79; # ?
  $http_header121 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header121 && $pcre_agent79; # [
  $http_header121 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header121 && $pcre_agent79; # ]
  #$http_header121 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header121 && $pcre_agent79; # ^
  $http_header121 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header121 && $pcre_agent79; # {
  $http_header121 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header121 && $pcre_agent79; # }
  #$pcre_uri73 =~ s/(?<!\x5C)\x24//g         if $pcre_uri73; # $
  #$pcre_agent79 =~ s/(?<!\x5C)\x24//g         if $pcre_agent79; # $

#perl -e '$abc1="1|20 21|2|22 24|3";while($abc1=~/(?<!\x5C)\|(.*?)\|/g){$toto1=$1;print "abc1:$abc1\ntoto1:$toto1\n";$toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g; print "$toto1\n"; $abc1=~s/(?<!\x5C)\|.*?\|/$toto1/}; print "final:$abc1\n"'
  while($http_uri03 && $http_uri03=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri03=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri08 && $http_uri08=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri08=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri13 && $http_uri13=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri13=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
   while($http_uri18 && $http_uri18=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri18=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri23 && $http_uri23=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri23=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri28 && $http_uri28=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri28=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri33 && $http_uri33=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri33=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri38 && $http_uri38=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri38=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri43 && $http_uri43=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri43=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri48 && $http_uri48=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri48=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri53 && $http_uri53=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri53=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri58 && $http_uri58=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri58=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri63 && $http_uri63=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri63=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_header68 && $http_header68=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header68=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_header121 && $http_header121=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header121=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  # ne pas faire d'echappement sur la pcre ($pcre_uri73)
  #while($http_header74 && $http_header74=~/(?<!\x5C)\|(.*?)\|/g) {
  # my $toto1=$1;
  # $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
  # $http_header74=~s/(?<!\x5C)\|.*?\|/$toto1/;
  #}
  # ne pas faire d'echappement sur la pcre ($pcre_agent79)
  my $abc1=0;
  my $httppcreagent=0;
  my $httpagentshort=0;
  my $httpagentshort_depth=0;
  my $httpagentshort_equal=0;
  my $httpreferer=0;
  my $httphost=0;
  my $pcrereferer=0;
  my $pcrehost=0;
  my @tableauuri1;
  my @tableauuridistance1;
  if( $pcre_uri73 && $http_uri03 && $pcre_uri73=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouvé grep3a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri03 && $http_uri03=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouvé grep3b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri03 && $http_uri03=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouvé grep3c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri08 && $pcre_uri73=~/\Q$http_uri08\E/i ) {
   undef $http_uri08;
   print "ok trouvé grep8a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri08 && $http_uri08=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri08\E/i ) {
   undef $http_uri08;
   print "ok trouvé grep8b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri08 && $http_uri08=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri08\E/i ) {
   undef $http_uri08;
   print "ok trouvé grep8c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri13 && $pcre_uri73=~/\Q$http_uri13\E/i ) {
   undef $http_uri13;
   print "ok trouvé grep13a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri13 && $http_uri13=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri13\E/i ) {
   undef $http_uri13;
   print "ok trouvé grep13b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri13 && $http_uri13=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri13\E/i ) {
   undef $http_uri13;
   print "ok trouvé grep13c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri18 && $pcre_uri73=~/\Q$http_uri18\E/i ) {
   undef $http_uri18;
   print "ok trouvé grep18a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri18 && $http_uri18=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri18\E/i ) {
   undef $http_uri18;
   print "ok trouvé grep18b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri18 && $http_uri18=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri18\E/i ) {
   undef $http_uri18;
   print "ok trouvé grep18c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri23 && $pcre_uri73=~/\Q$http_uri23\E/i ) {
   undef $http_uri23;
   print "ok trouvé grep23a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri23 && $http_uri23=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri23\E/i ) {
   undef $http_uri23;
   print "ok trouvé grep23b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri23 && $http_uri23=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri23\E/i ) {
   undef $http_uri23;
   print "ok trouvé grep23c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri28 && $pcre_uri73=~/\Q$http_uri28\E/i ) {
   undef $http_uri28;
   print "ok trouvé grep28a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri28 && $http_uri28=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri28\E/i ) {
   undef $http_uri28;
   print "ok trouvé grep28b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri28 && $http_uri28=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri28\E/i ) {
   undef $http_uri28;
   print "ok trouvé grep28c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri33 && $pcre_uri73=~/\Q$http_uri33\E/i ) {
   undef $http_uri33;
   print "ok trouvé grep33a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri33 && $http_uri33=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri33\E/i ) {
   undef $http_uri33;
   print "ok trouvé grep33b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri33 && $http_uri33=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri33\E/i ) {
   undef $http_uri33;
   print "ok trouvé grep33c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri38 && $pcre_uri73=~/\Q$http_uri38\E/i ) {
   undef $http_uri38;
   print "ok trouvé grep38a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri38 && $http_uri38=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri38\E/i ) {
   undef $http_uri38;
   print "ok trouvé grep38b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri38 && $http_uri38=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri38\E/i ) {
   undef $http_uri38;
   print "ok trouvé grep38c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri43 && $pcre_uri73=~/\Q$http_uri43\E/i ) {
   undef $http_uri43;
   print "ok trouvé grep43a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri43 && $http_uri43=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri43\E/i ) {
   undef $http_uri43;
   print "ok trouvé grep43b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri43 && $http_uri43=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri43\E/i ) {
   undef $http_uri43;
   print "ok trouvé grep43c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri48 && $pcre_uri73=~/\Q$http_uri48\E/i ) {
   undef $http_uri48;
   print "ok trouvé grep48a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri48 && $http_uri48=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri48\E/i ) {
   undef $http_uri48;
   print "ok trouvé grep48b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri48 && $http_uri48=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri48\E/i ) {
   undef $http_uri48;
   print "ok trouvé grep48c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri53 && $pcre_uri73=~/\Q$http_uri53\E/i ) {
   undef $http_uri53;
   print "ok trouvé grep53a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri53 && $http_uri53=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri53\E/i ) {
   undef $http_uri53;
   print "ok trouvé grep53b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri53 && $http_uri53=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri53\E/i ) {
   undef $http_uri53;
   print "ok trouvé grep53c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri58 && $pcre_uri73=~/\Q$http_uri58\E/i ) {
   undef $http_uri58;
   print "ok trouvé grep58a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri58 && $http_uri58=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri58\E/i ) {
   undef $http_uri58;
   print "ok trouvé grep58b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri58 && $http_uri58=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri58\E/i ) {
   undef $http_uri58;
   print "ok trouvé grep58c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri63 && $pcre_uri73=~/\Q$http_uri63\E/i ) {
   undef $http_uri63;
   print "ok trouvé grep63a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri63 && $http_uri63=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri63\E/i ) {
   undef $http_uri63;
   print "ok trouvé grep63b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri63 && $http_uri63=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri63\E/i ) {
   undef $http_uri63;
   print "ok trouvé grep63c\n" if $debug1;
  }

     if( $http_header68 && $http_header68 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~ s/\QUser-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser-Agent\: \E$/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser-Agent\:\E$/i ) { undef($http_header68) }
                           $http_header68 =~ s/\Q\x0D\x0A\E/\$/i if $http_header68;
     if( $http_header121 && $http_header121 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~ s/\QUser-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser-Agent\: \E$/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser-Agent\:\E$/i ) { undef($http_header121) }
                           $http_header121 =~ s/\Q\x0D\x0A\E/\$/i if $http_header121;
  $pcre_agent79 =~ s/\Q^User\-Agent\x3A\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User-Agent\x3A\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User\-Agent\x3A \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser\-Agent\x3A\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser\-Agent\x3A \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User-Agent\x3A\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User-Agent\x3A \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser-Agent\x3A\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser-Agent\x3A \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User\-Agent\:\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User\-Agent\: \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser\-Agent\:\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser\-Agent\: \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User-Agent\:\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User-Agent\: \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser-Agent\:\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser-Agent\: \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User\-Agent\x3A\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser\-Agent\x3A\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User-Agent\x3A\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser-Agent\x3A\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User\-Agent\:\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser\-Agent\:\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User-Agent\:\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser-Agent\:\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q\x0D\x0A\E/\$/i if $pcre_agent79;
  $pcre_agent79 =~ s/\\r\?\$/\$/i if $pcre_agent79;
  $pcre_agent79 =~ s/\\r\$/\$/i if $pcre_agent79;
     if( $http_header68  && $http_header68 =~ s/\Q^Referer\x3A\x20\E/^/i ) { $pcrereferer = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\Q^Referer\x3A \E/^/i ) { $pcrereferer = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\QReferer\x3A\x20\E/^/i ) { $pcrereferer = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\QReferer\x3A \E/^/i ) { $pcrereferer = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\Q^Referer\x3A\E/^/i ) { $pcrereferer = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\QReferer\x3A\E/^/i ) { $pcrereferer = $http_header68; undef $http_header68 }
     if( $http_header121 && $http_header121 =~ s/\Q^Referer\x3A\x20\E/^/i ) { $pcrereferer = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\Q^Referer\x3A \E/^/i ) { $pcrereferer = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\QReferer\x3A\x20\E/^/i ) { $pcrereferer = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\QReferer\x3A \E/^/i ) { $pcrereferer = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\Q^Referer\x3A\E/^/i ) { $pcrereferer = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\QReferer\x3A\E/^/i ) { $pcrereferer = $http_header121; undef $http_header121 }

     if( $http_header68  && $http_header68 =~ s/\Q^Host\x3A\x20\E/^/i ) { $pcrehost = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\Q^Host\x3A \E/^/i ) { $pcrehost = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\QHost\x3A\x20\E/^/i ) { $pcrehost = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\QHost\x3A \E/^/i ) { $pcrehost = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\Q^Host\x3A\E/^/i ) { $pcrehost = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\QHost\x3A\E/^/i ) { $pcrehost = $http_header68; undef $http_header68 }
     if( $http_header121 && $http_header121 =~ s/\Q^Host\x3A\x20\E/^/i ) { $pcrehost = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\Q^Host\x3A \E/^/i ) { $pcrehost = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\QHost\x3A\x20\E/^/i ) { $pcrehost = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\QHost\x3A \E/^/i ) { $pcrehost = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\Q^Host\x3A\E/^/i ) { $pcrehost = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\QHost\x3A\E/^/i ) { $pcrehost = $http_header121; undef $http_header121 }

  $pcrereferer =~ s/(?<!\x5C)\x28/\x5C\x28/g if $pcrereferer; # (
  $pcrereferer =~ s/(?<!\x5C)\x29/\x5C\x29/g if $pcrereferer; # )
  $pcrereferer =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $pcrereferer; # *
  $pcrereferer =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $pcrereferer; # +
  $pcrereferer =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $pcrereferer; # -
  $pcrereferer =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $pcrereferer; # .
  $pcrereferer =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $pcrereferer; # /
  $pcrereferer =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $pcrereferer; # ?
  $pcrereferer =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $pcrereferer; # [
  $pcrereferer =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $pcrereferer; # ]
  #$pcrereferer =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $pcrereferer; # ^
  $pcrereferer =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $pcrereferer; # {
  $pcrereferer =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $pcrereferer; # }

  if( $pcrereferer !~ /\\x/ && $pcrereferer =~ /^\^/ && $pcrereferer !~ /^\^\\\-\$$/ )
  {
   $pcrereferer =~ s/\\//g;
   $pcrereferer =~ s/^\^//g;
   $pcrereferer =~ s/\$$//g;
   $httpreferer = $pcrereferer;
   $pcrereferer = 0;
  }

  if( $pcrehost !~ /\\x/ && $pcrehost =~ /^\^/ && $pcrehost !~ /^\^\\\-\$$/ )
  {
   $pcrehost =~ s/\\//g;
   $pcrehost =~ s/^\^//g;
   $pcrehost =~ s/\$$//g;
   $httphost = $pcrehost;
   $pcrehost = 0;
  }

     if( $pcre_agent79   && $pcre_agent79  =~ s/\Q^Referer\x3A\x20\E/^/i ) { $pcrereferer = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\Q^Referer\x3A \E/^/i ) { $pcrereferer = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\QReferer\x3A\x20\E/^/i ) { $pcrereferer = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\QReferer\x3A \E/^/i ) { $pcrereferer = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\Q^Referer\x3A\E/^/i ) { $pcrereferer = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\QReferer\x3A\E/^/i ) { $pcrereferer = $pcre_agent79; undef $pcre_agent79 }

     if( $pcre_agent79   && $pcre_agent79  =~ s/\Q^Host\x3A\x20\E/^/i ) { $pcrehost = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\Q^Host\x3A \E/^/i ) { $pcrehost = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\QHost\x3A\x20\E/^/i ) { $pcrehost = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\QHost\x3A \E/^/i ) { $pcrehost = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\Q^Host\x3A\E/^/i ) { $pcrehost = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\QHost\x3A\E/^/i ) { $pcrehost = $pcre_agent79; undef $pcre_agent79 }

  if( $pcrereferer )
  {
   $pcrereferer =~ s/\Q^[^\r\n]+?\E//i;
   $pcrereferer =~ s/\Q^[^\r\n]+\E//i;
   $pcrereferer =~ s/\Q^[^\r\n]*?\E//i;
   $pcrereferer =~ s/\Q^[^\r\n]*\E//i;
   $pcrereferer =~ s/\Q^[^\n]+?\E//i;
   $pcrereferer =~ s/\Q^[^\n]+\E//i;
   $pcrereferer =~ s/\Q^[^\n]*?\E//i;
   $pcrereferer =~ s/\Q^[^\n]*\E//i;
  }

  if( $pcrehost )
  {
   $pcrehost =~ s/\Q^[^\r\n]+?\E//i;
   $pcrehost =~ s/\Q^[^\r\n]+\E//i;
   $pcrehost =~ s/\Q^[^\r\n]*?\E//i;
   $pcrehost =~ s/\Q^[^\r\n]*\E//i;
   $pcrehost =~ s/\Q^[^\n]+?\E//i;
   $pcrehost =~ s/\Q^[^\n]+\E//i;
   $pcrehost =~ s/\Q^[^\n]*?\E//i;
   $pcrehost =~ s/\Q^[^\n]*\E//i;
  }

  if( $pcre_agent79 )
  {
   $pcre_agent79 =~ s/\Q^[^\r\n]+?\E//i;
   $pcre_agent79 =~ s/\Q^[^\r\n]+\E//i;
   $pcre_agent79 =~ s/\Q^[^\r\n]*?\E//i;
   $pcre_agent79 =~ s/\Q^[^\r\n]*\E//i;
   $pcre_agent79 =~ s/\Q^[^\n]+?\E//i;
   $pcre_agent79 =~ s/\Q^[^\n]+\E//i;
   $pcre_agent79 =~ s/\Q^[^\n]*?\E//i;
   $pcre_agent79 =~ s/\Q^[^\n]*\E//i;
  }

  # http_user_agent short
  if( $http_header68 && $http_header121 && length($http_header68) >= length($http_header121) )
  {
   $httpagentshort= "$http_header68" if $http_header68;
  }
  elsif( $http_header68 && $http_header121 && length($http_header121) >= length($http_header68) )
  {
   $httpagentshort= "$http_header121" if $http_header121;
  }
  elsif( $http_header68 && !$http_header121 )
  {
   $httpagentshort= "$http_header68" if $http_header68;
  }
  elsif( $http_header121 && !$http_header68 )
  {
   $httpagentshort= "$http_header121" if $http_header121;
  }

  while( $httpagentshort =~ /\\x(..)/g )
  {
   my $tempochr=chr(hex("$1"));
   $httpagentshort =~ s/\\x(..)/$tempochr/;
  }
  $httpagentshort =~ s/(?:\\(?!$)(?:x[a-f0-9]{2})?|\^|\$)//g;

  if( $pcre_agent79 && $http_header68 && $pcre_agent79=~/\Q$http_header68\E/i ) {
   undef $http_header68;
   print "ok trouvé grep68a\n" if $debug1;
  }
  elsif( $pcre_agent79 && $http_header68 && $http_header68=~s/\&/\\x26/g && $pcre_agent79=~/\Q$http_header68\E/i ) {
   undef $http_header68;
   print "ok trouvé grep68b\n" if $debug1;
  }
  elsif( $pcre_agent79 && $http_header68 && $http_header68=~s/\=/\\x3D/g && $pcre_agent79=~/\Q$http_header68\E/i ) {
   undef $http_header68;
   print "ok trouvé grep68c\n" if $debug1;
  }
  if( $pcre_agent79 && $http_header121 && $pcre_agent79=~/\Q$http_header121\E/i ) {
   undef $http_header121;
   print "ok trouvé grep121a\n" if $debug1;
  }
  elsif( $pcre_agent79 && $http_header121 && $http_header121=~s/\&/\\x26/g && $pcre_agent79=~/\Q$http_header121\E/i ) {
   undef $http_header121;
   print "ok trouvé grep121b\n" if $debug1;
  }
  elsif( $pcre_agent79 && $http_header121 && $http_header121=~s/\=/\\x3D/g && $pcre_agent79=~/\Q$http_header121\E/i ) {
   undef $http_header121;
   print "ok trouvé grep121c\n" if $debug1;
  }

  # one uri
  #$abc1= "$http_uri03" if $http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri08" if $http_uri08 && !$http_uri03 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri13" if $http_uri13 && !$http_uri03 && !$http_uri08 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri18" if $http_uri18 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri23" if $http_uri23 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri28" if $http_uri28 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri33" if $http_uri33 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri38" if $http_uri38 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri43" if $http_uri43 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri48" if $http_uri48 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri53" if $http_uri53 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri58" if $http_uri58 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri63" if $http_uri63 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$pcre_uri73;
  $abc1= "$pcre_uri73" if $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;

  # check again if header content need escape
  $http_header68 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header68; # (
  $http_header68 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header68; # )
  $http_header68 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header68; # *
  $http_header68 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header68; # +
  $http_header68 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header68; # -
  $http_header68 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header68; # .
  $http_header68 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header68; # /
  $http_header68 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header68; # ?
  $http_header68 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header68; # [
  $http_header68 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header68; # ]
  #$http_header68 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header68; # ^
  $http_header68 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header68; # {
  $http_header68 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header68; # }
  $http_header121 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header121; # (
  $http_header121 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header121; # )
  $http_header121 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header121; # *
  $http_header121 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header121; # +
  $http_header121 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header121; # -
  $http_header121 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header121; # .
  $http_header121 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header121; # /
  $http_header121 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header121; # ?
  $http_header121 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header121; # [
  $http_header121 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header121; # ]
  #$http_header121 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header121; # ^
  $http_header121 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header121; # {
  $http_header121 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header121; # }

  # one header
  $httppcreagent= "$http_header68" if $http_header68 && !$http_header121 && !$pcre_agent79 && $http_header68 =~ /(?:\\|\^|\$)/;
  $httppcreagent= "$http_header121" if $http_header121 && !$http_header68 && !$pcre_agent79 && $http_header121 =~ /(?:\\|\^|\$)/;
  $httppcreagent= "$pcre_agent79" if $pcre_agent79 && !$http_header68 && !$http_header121;

  # two headers
  if( ($http_header68 && $http_header121) && (defined($distance124)||defined($distance125)||defined($distance128)||defined($distance129)) ) {
   $httppcreagent= "(?:$http_header68.*?$http_header121)" if $http_header68 && $http_header121;
  }

  # two uri
  if( !$pcre_uri73 && (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) ) {
   @tableauuridistance1 = ( $http_uri03, $http_uri08 ) if $http_uri03 && $http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  }
  elsif( $pcre_uri73 && (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) ) {
   $abc1= "(?:$http_uri03.*?$http_uri08)" if $http_uri03 && $http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  }
  elsif( !(defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) ) {
   if( $http_uri03 && $http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri08 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri03, $http_uri08 ) if $http_uri03 && $http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
   else
   {
   $abc1= "(?:$http_uri03.*?$http_uri08|$http_uri08.*?$http_uri03)" if $http_uri03 && $http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri13|$http_uri13.*?$http_uri03)" if $http_uri03 && $http_uri13 && !$http_uri08 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri18|$http_uri18.*?$http_uri03)" if $http_uri03 && $http_uri18 && !$http_uri08 && !$http_uri13 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri23|$http_uri23.*?$http_uri03)" if $http_uri03 && $http_uri23 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri28|$http_uri28.*?$http_uri03)" if $http_uri03 && $http_uri28 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri33|$http_uri33.*?$http_uri03)" if $http_uri03 && $http_uri33 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri38|$http_uri38.*?$http_uri03)" if $http_uri03 && $http_uri38 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri43|$http_uri43.*?$http_uri03)" if $http_uri03 && $http_uri43 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri48|$http_uri48.*?$http_uri03)" if $http_uri03 && $http_uri48 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri53|$http_uri53.*?$http_uri03)" if $http_uri03 && $http_uri53 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri58|$http_uri58.*?$http_uri03)" if $http_uri03 && $http_uri58 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri63|$http_uri63.*?$http_uri03)" if $http_uri03 && $http_uri63 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$pcre_uri73|$pcre_uri73.*?$http_uri03)" if $http_uri03 && $pcre_uri73 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri08.*?$pcre_uri73|$pcre_uri73.*?$http_uri08)" if $http_uri08 && $pcre_uri73 && !$http_uri03 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri13.*?$pcre_uri73|$pcre_uri73.*?$http_uri13)" if $http_uri13 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri18.*?$pcre_uri73|$pcre_uri73.*?$http_uri18)" if $http_uri18 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri23.*?$pcre_uri73|$pcre_uri73.*?$http_uri23)" if $http_uri23 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri28.*?$pcre_uri73|$pcre_uri73.*?$http_uri28)" if $http_uri28 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri33.*?$pcre_uri73|$pcre_uri73.*?$http_uri33)" if $http_uri33 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri38.*?$pcre_uri73|$pcre_uri73.*?$http_uri38)" if $http_uri38 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri43.*?$pcre_uri73|$pcre_uri73.*?$http_uri43)" if $http_uri43 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri48.*?$pcre_uri73|$pcre_uri73.*?$http_uri48)" if $http_uri48 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri53.*?$pcre_uri73|$pcre_uri73.*?$http_uri53)" if $http_uri53 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri58.*?$pcre_uri73|$pcre_uri73.*?$http_uri58)" if $http_uri58 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri63;
   $abc1= "(?:$http_uri63.*?$pcre_uri73|$pcre_uri73.*?$http_uri63)" if $http_uri63 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58;
   }
  }

  # three uri
  if( !$pcre_uri73 && (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) ) {
   @tableauuridistance1 = ( $http_uri03, $http_uri08, $http_uri13 ) if $http_uri03 && $http_uri08 && $http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  }
  elsif( $pcre_uri73 && (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) ) {
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13)" if $http_uri03 && $http_uri08 && $http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  }
  elsif( !(defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) ) {
   if( $http_uri03 && $http_uri08 && $http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri08 !~ /\\x|^\^|\$$/ ) or ( $http_uri13 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri03, $http_uri08, $http_uri13 ) if $http_uri03 && $http_uri08 && $http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
   else
   {
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri18|$http_uri03.*$http_uri18.*$http_uri08|$http_uri18.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri18.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri18 && !$http_uri13 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri23|$http_uri03.*$http_uri23.*$http_uri08|$http_uri23.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri23.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri23 && !$http_uri13 && !$http_uri18 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri28|$http_uri03.*$http_uri28.*$http_uri08|$http_uri28.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri28.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri28 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri33|$http_uri03.*$http_uri33.*$http_uri08|$http_uri33.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri33.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri33 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri38|$http_uri03.*$http_uri38.*$http_uri08|$http_uri38.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri38.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri38 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri43|$http_uri03.*$http_uri43.*$http_uri08|$http_uri43.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri43.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri43 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri48|$http_uri03.*$http_uri48.*$http_uri08|$http_uri48.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri48.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri48 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri53|$http_uri03.*$http_uri53.*$http_uri08|$http_uri53.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri53.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri53 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri58|$http_uri03.*$http_uri58.*$http_uri08|$http_uri58.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri58.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri58 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri63|$http_uri03.*$http_uri63.*$http_uri08|$http_uri63.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri63.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri63 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$pcre_uri73|$http_uri03.*$pcre_uri73.*$http_uri08|$pcre_uri73.*$http_uri08.*$http_uri03|$http_uri08.*$pcre_uri73.*$http_uri03)" if $http_uri03 && $http_uri08 && $pcre_uri73 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   }
  }

  # four uri
  if( !$pcre_uri73 && (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) ) {
    @tableauuridistance1 = ( $http_uri03, $http_uri08, $http_uri13, $http_uri18 ) if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;

  } elsif( $pcre_uri73 && (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) ) {
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri18)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18;

  } elsif( !(defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) ) {
   if( $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri08 !~ /\\x|^\^|\$$/ ) or ( $http_uri13 !~ /\\x|^\^|\$$/ ) or ( $http_uri18 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri03, $http_uri08, $http_uri13, $http_uri18 ) if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
   else
   {
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri18|$http_uri03.*$http_uri08.*$http_uri18.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri18|$http_uri03.*$http_uri13.*$http_uri18.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri18.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri18|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri18|$http_uri08.*$http_uri03.*$http_uri18.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri18|$http_uri13.*$http_uri03.*$http_uri18.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri18.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri18|$http_uri18.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri18.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri18.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri18.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri23|$http_uri03.*$http_uri08.*$http_uri23.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri23|$http_uri03.*$http_uri13.*$http_uri23.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri23.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri23|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri23|$http_uri08.*$http_uri03.*$http_uri23.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri23|$http_uri13.*$http_uri03.*$http_uri23.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri23.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri23|$http_uri23.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri23.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri23.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri23.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri23 && !$http_uri18 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri28|$http_uri03.*$http_uri08.*$http_uri28.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri28|$http_uri03.*$http_uri13.*$http_uri28.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri28.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri28|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri28|$http_uri08.*$http_uri03.*$http_uri28.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri28|$http_uri13.*$http_uri03.*$http_uri28.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri28.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri28|$http_uri28.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri28.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri28.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri28.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri28 && !$http_uri18 && !$http_uri23 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri33|$http_uri03.*$http_uri08.*$http_uri33.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri33|$http_uri03.*$http_uri13.*$http_uri33.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri33.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri33|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri33|$http_uri08.*$http_uri03.*$http_uri33.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri33|$http_uri13.*$http_uri03.*$http_uri33.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri33.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri33|$http_uri33.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri33.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri33.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri33.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri33 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri38|$http_uri03.*$http_uri08.*$http_uri38.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri38|$http_uri03.*$http_uri13.*$http_uri38.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri38.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri38|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri38|$http_uri08.*$http_uri03.*$http_uri38.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri38|$http_uri13.*$http_uri03.*$http_uri38.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri38.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri38|$http_uri38.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri38.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri38.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri38.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri38 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri43|$http_uri03.*$http_uri08.*$http_uri43.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri43|$http_uri03.*$http_uri13.*$http_uri43.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri43.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri43|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri43|$http_uri08.*$http_uri03.*$http_uri43.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri43|$http_uri13.*$http_uri03.*$http_uri43.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri43.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri43|$http_uri43.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri43.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri43.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri43.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri43 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri48|$http_uri03.*$http_uri08.*$http_uri48.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri48|$http_uri03.*$http_uri13.*$http_uri48.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri48.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri48|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri48|$http_uri08.*$http_uri03.*$http_uri48.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri48|$http_uri13.*$http_uri03.*$http_uri48.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri48.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri48|$http_uri48.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri48.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri48.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri48.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri48 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri53|$http_uri03.*$http_uri08.*$http_uri53.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri53|$http_uri03.*$http_uri13.*$http_uri53.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri53.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri53|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri53|$http_uri08.*$http_uri03.*$http_uri53.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri53|$http_uri13.*$http_uri03.*$http_uri53.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri53.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri53|$http_uri53.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri53.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri53.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri53.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri53 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri58|$http_uri03.*$http_uri08.*$http_uri58.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri58|$http_uri03.*$http_uri13.*$http_uri58.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri58.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri58|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri58|$http_uri08.*$http_uri03.*$http_uri58.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri58|$http_uri13.*$http_uri03.*$http_uri58.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri58.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri58|$http_uri58.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri58.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri58.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri58.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri58 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri63|$http_uri03.*$http_uri08.*$http_uri63.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri63|$http_uri03.*$http_uri13.*$http_uri63.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri63.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri63|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri63|$http_uri08.*$http_uri03.*$http_uri63.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri63|$http_uri13.*$http_uri03.*$http_uri63.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri63.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri63|$http_uri63.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri63.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri63.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri63.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri63 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$pcre_uri73|$http_uri03.*$http_uri08.*$pcre_uri73.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$pcre_uri73|$http_uri03.*$http_uri13.*$pcre_uri73.*$http_uri08|$http_uri08.*$http_uri13.*$pcre_uri73.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$pcre_uri73|$http_uri08.*$http_uri03.*$http_uri13.*$pcre_uri73|$http_uri08.*$http_uri03.*$pcre_uri73.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$pcre_uri73|$http_uri13.*$http_uri03.*$pcre_uri73.*$http_uri08|$http_uri13.*$http_uri08.*$pcre_uri73.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$pcre_uri73|$pcre_uri73.*$http_uri03.*$http_uri08.*$http_uri13|$pcre_uri73.*$http_uri03.*$http_uri13.*$http_uri08|$pcre_uri73.*$http_uri13.*$http_uri03.*$http_uri08|$pcre_uri73.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $pcre_uri73 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   }
  }

  # five uri
  if( !$pcre_uri73 && (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && (defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
   @tableauuridistance1 = ( $http_uri03, $http_uri08, $http_uri13, $http_uri18, $http_uri23 ) if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  }
  elsif( $pcre_uri73 && (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && (defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri18.*$http_uri23)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23;
  }
  elsif( !(defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && !(defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
   if( $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri08 !~ /\\x|^\^|\$$/ ) or ( $http_uri13 !~ /\\x|^\^|\$$/ ) or ( $http_uri18 !~ /\\x|^\^|\$$/ ) or ( $http_uri23 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri03, $http_uri08, $http_uri13, $http_uri18, $http_uri23 ) if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
  }

  # six uri
  if( !$pcre_uri73 && (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && (defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) && (defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) ) {
   @tableauuridistance1 = ( $http_uri03, $http_uri08, $http_uri13, $http_uri18, $http_uri23, $http_uri28 ) if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && $http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  }
  elsif( $pcre_uri73 && (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && (defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) && (defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) ) {
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri18.*$http_uri23.*$http_uri28)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && $http_uri28;
  }
  elsif( !(defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && !(defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) && !(defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) ) {
   if( $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && $http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri08 !~ /\\x|^\^|\$$/ ) or ( $http_uri13 !~ /\\x|^\^|\$$/ ) or ( $http_uri18 !~ /\\x|^\^|\$$/ ) or ( $http_uri23 !~ /\\x|^\^|\$$/ ) or ( $http_uri28 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri03, $http_uri08, $http_uri13, $http_uri18, $http_uri23, $http_uri28 ) if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && $http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
  }

  # seven uri
  if( !$pcre_uri73 && (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && (defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) && (defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) && (defined($distance34)||defined($distance35)||defined($distance36)||defined($distance37)) ) {
   @tableauuridistance1 = ( $http_uri03, $http_uri08, $http_uri13, $http_uri18, $http_uri23, $http_uri28, $http_uri33 ) if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && $http_uri28 && $http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  }
  elsif( $pcre_uri73 && (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && (defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) && (defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) && (defined($distance34)||defined($distance35)||defined($distance36)||defined($distance37)) ) {
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri18.*$http_uri23.*$http_uri28.*$http_uri33)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && $http_uri28 && $http_uri33;
  }
  elsif( (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && (defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) && (defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) && (defined($distance34)||defined($distance35)||defined($distance36)||defined($distance37)) ) {
   if( $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && $http_uri28 && $http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri08 !~ /\\x|^\^|\$$/ ) or ( $http_uri13 !~ /\\x|^\^|\$$/ ) or ( $http_uri18 !~ /\\x|^\^|\$$/ ) or ( $http_uri23 !~ /\\x|^\^|\$$/ ) or ( $http_uri28 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri03, $http_uri08, $http_uri13, $http_uri18, $http_uri23, $http_uri28, $http_uri33 ) if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && $http_uri28 && $http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
  }

  foreach( @tableauuridistance1 )
  {
   s/\\(?!x)//g;
   while( /\\x(..)/g )
   {
    my $tempochr=chr(hex("$1"));
    $_ =~ s/\\x(..)/$tempochr/;
   }
  }

  # uri:
  my $abc1_nocase=0;
     $abc1_nocase=$http_urifast5    if $http_urifast5;
     $abc1_nocase=$http_urinocase5  if $http_urinocase5;
     $abc1_nocase=$http_urifast9    if $http_urifast9;
     $abc1_nocase=$http_urinocase10 if $http_urinocase10;
     $abc1_nocase=$http_urifast14   if $http_urifast14;
     $abc1_nocase=$http_urinocase12 if $http_urinocase12;
     $abc1_nocase=$http_urifast18   if $http_urifast18;
     $abc1_nocase=$http_urinocase15 if $http_urinocase15;
     $abc1_nocase=$http_urifast23   if $http_urifast23;
     $abc1_nocase=$http_urinocase19 if $http_urinocase19;
     $abc1_nocase=$http_urifast27   if $http_urifast27;
     $abc1_nocase=$http_urinocase22 if $http_urinocase22;
     $abc1_nocase=$http_urifast32   if $http_urifast32;
     $abc1_nocase=$http_urinocase26 if $http_urinocase26;
     $abc1_nocase=$http_urifast36   if $http_urifast36;
     $abc1_nocase=$http_urinocase29 if $http_urinocase29;
     $abc1_nocase=$http_urifast41   if $http_urifast41;
     $abc1_nocase=$http_urinocase33 if $http_urinocase33;
     $abc1_nocase=$http_urifast44   if $http_urifast44;
     $abc1_nocase=$http_urinocase36 if $http_urinocase36;
     $abc1_nocase=$http_urifast49   if $http_urifast49;
     $abc1_nocase=$http_urinocase40 if $http_urinocase40;
     $abc1_nocase=$http_urifast54   if $http_urifast54;
     $abc1_nocase=$http_urinocase43 if $http_urinocase43;
     $abc1_nocase=$http_urifast58   if $http_urifast58;
     $abc1_nocase=$http_urinocase47 if $http_urinocase47;
     $abc1_nocase=$http_urifast62   if $http_urifast62;
     $abc1_nocase=$http_urinocase50 if $http_urinocase50;
     $abc1_nocase=$http_urinocase54 if $http_urinocase54;
     $abc1_nocase=$http_urinocase57 if $http_urinocase57;
     $abc1_nocase=$http_urinocase61 if $http_urinocase61;
     $abc1_nocase=$http_urinocase64 if $http_urinocase64;
     $abc1_nocase=$http_urinocase68 if $http_urinocase68;
     $abc1_nocase=$http_urinocase71 if $http_urinocase71;
     $abc1_nocase=$http_urinocase75 if $http_urinocase75;
     $abc1_nocase=$http_urinocase78 if $http_urinocase78;
     $abc1_nocase=$http_urinocase82 if $http_urinocase82;
     $abc1_nocase=$http_urinocase85 if $http_urinocase85;
     $abc1_nocase=$http_urinocase89 if $http_urinocase89;
     $abc1_nocase=$http_urinocase92 if $http_urinocase92;

  # header:
  my $httppcreagent_nocase=0;
     $httppcreagent_nocase=$http_headernocase96 if $http_headernocase96;
     $httppcreagent_nocase=$http_headernocase99 if $http_headernocase99;
     $httppcreagent_nocase=$http_headerfast122  if $http_headerfast122;
     $httppcreagent_nocase=$http_headernocase123 if $http_headernocase123;
     $httppcreagent_nocase=$http_headerfast126  if $http_headerfast126;
     $httppcreagent_nocase=$http_headernocase127 if $http_headernocase127;

  if( $httpagentshort && $httppcreagent )
  {
   my $tempopcreagent = $httppcreagent;
   my $tempopcreagent2;
   while( $tempopcreagent && $tempopcreagent =~ /\\(?!$)x([a-f0-9]{2})?/g ) {
    my $toto1=chr(hex($1)) if $1;
    print "uaici1a: $toto1\n" if $debug1 && $toto1;
    $tempopcreagent =~ s/\\(?!$)x([a-f0-9]{2})?/$toto1/ if $toto1;
   }
   $tempopcreagent =~ s/\\(?!$)(?:x[a-f0-9]{2})?//g;
   print "uaici1b: $httpagentshort\n" if $debug1;
   print "uaici1c: $httppcreagent\n" if $debug1;
   print "uaici1d: $tempopcreagent\n" if $debug1;
   if( $httpagentshort eq $tempopcreagent )
   {
    print "tempopcreagent1: $tempopcreagent\n" if $debug1;
    undef $httppcreagent;
    undef $tempopcreagent;
   }
   elsif( $tempopcreagent =~ /^\^(?!\-\$)([^\$]*?)\$/ && $httpagentshort eq $1 )
   {
    print "uaici1e: $1\n" if $debug1;
    $httpagentshort_equal=length($tempopcreagent)-2;
    undef $httppcreagent;
    undef $tempopcreagent;
    undef $tempopcreagent2;
    print "uaici1f: $httpagentshort_equal\n" if $debug1;
   }
   elsif( $tempopcreagent =~ /^\^(.*)/ && $httpagentshort eq $1 )
   {
    print "uaici1g: $1\n" if $debug1;
    $httpagentshort_depth = length($tempopcreagent)-1;
    undef $httppcreagent;
    undef $tempopcreagent;
    undef $tempopcreagent2;
    print "uaici1h: $httpagentshort_depth\n" if $debug1;
   }
  }

 if( !@year2 || grep(/$metadatacreatedyear/, @year2) )
 {
  print "httpuricourt1: $etmsg1, ".lc($httpuricourt) if $debug1 && $httpuricourt; print ", depth: $http_uridepth" if $debug1 && $httpuricourt && $http_uridepth; print ", offset: $http_urioffset" if $debug1 && $httpuricourt && $http_urioffset; print "\n" if $debug1 && $httpuricourt;
  print "httpurilong1: $etmsg1, @tableauuri1\n" if $debug1 && @tableauuri1;
  print "tableaupcreuri1: $etmsg1, $abc1, $abc1_nocase\n" if $debug1 && $abc1;
  print "tableaupcreagent1: $etmsg1, $httppcreagent, $httppcreagent_nocase\n" if $debug1 && $httppcreagent;
  print "httpagentshort1: $etmsg1, ".lc($httpagentshort) if $debug1 && $httpagentshort; print ", depth=$httpagentshort_depth" if $debug1 && $httpagentshort_depth; print ", equal=$httpagentshort_equal" if $debug1 && $httpagentshort_equal; print "\n" if $debug1 && $httpagentshort;
  print "tableauhttpmethod1: $etmsg1, $http_method1, $http_methodnocase1\n" if $debug1 && $http_method1;
  print "httpreferer1: $etmsg1, ".lc($httpreferer)."\n" if $debug1 && $httpreferer;
  print "tableaupcrereferer1: $etmsg1, $pcrereferer\n" if $debug1 && $pcrereferer;
  print "httpurilongdistance1: $etmsg1, @tableauuridistance1\n" if $debug1 && @tableauuridistance1;
  print "httphost1: $etmsg1, ".lc($httphost)."\n" if $debug1 && $httphost;
  print "tableaupcrehost1: $etmsg1, $pcrehost\n" if $debug1 && $pcrehost;
  print "http_urilen1: $etmsg1, $http_urilen1\n" if $debug1 && $http_urilen1;
  print "metadata_created_year1: $etmsg1, $metadatacreatedyear\n" if $debug1 && $metadatacreatedyear;

  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt), $http_uridepth, $http_urioffset ] if $httpuricourt && $http_uridepth && $http_urioffset;
  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt), $http_uridepth ] if $httpuricourt && $http_uridepth && !$http_urioffset;
  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt) ] if $httpuricourt && !$http_uridepth && !$http_urioffset;
  $hash{$etmsg1}{httpagentshort} = [ lc($httpagentshort), "" , $httpagentshort_equal ] if $httpagentshort && !$httpagentshort_depth && $httpagentshort_equal;
  $hash{$etmsg1}{httpagentshort} = [ lc($httpagentshort), $httpagentshort_depth ] if $httpagentshort && $httpagentshort_depth && !$httpagentshort_equal;
  $hash{$etmsg1}{httpagentshort} = [ lc($httpagentshort) ] if $httpagentshort && !$httpagentshort_depth;
  $hash{$etmsg1}{httpmethod} = [ $http_method1, $http_methodnocase1 ] if $http_method1;
  $hash{$etmsg1}{httpreferer} = [ lc($httpreferer) ] if $httpreferer;
  $hash{$etmsg1}{pcrereferer} = [ $pcrereferer ] if $pcrereferer;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{pcreagent} = [ $httppcreagent, $httppcreagent_nocase ] if $httppcreagent;
  $hash{$etmsg1}{httpurilong} = [ @tableauuri1 ] if @tableauuri1;
  $hash{$etmsg1}{httpurilongdistance} = [ @tableauuridistance1 ] if @tableauuridistance1;
  $hash{$etmsg1}{httphost} = [ lc($httphost) ] if $httphost;
  $hash{$etmsg1}{pcrehost} = [ $pcrehost ] if $pcrehost;
  $hash{$etmsg1}{httpurilen} = [ $http_urilen1 ] if $http_urilen1;
 }

  next;
 }

 # begin uricontent
# elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$urilen1)?(?:$httpmethod)?(?:$negateuricontent1)?\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:\s*(?:uri)?content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$pcreuri)?(?:$extracontentoptions)?$referencesidrev$/ )
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$urilen1)?(?:$httpmethod)?(?:$negateuricontent1)?\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:\s*(?:uri)?content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$pcreuri)?(?:$extracontentoptions)?$referencesidrev[^\n]*$createdat/ )
 {
  my $http_method2=0;
  my $http_methodnocase2=0;
  my $http_urioffset=0;
  my $http_uridepth=0;
  #
  if( $debug1 ){
   print "brut2: $_\n"; print "here2: 1: $1," if $1; print " 2: $2," if $2; print " 3: $3," if $3; print " 4: $4," if $4; print " 5: $5," if $5; print " 6: $6," if $6; print " 7: $7," if $7; print " 8: $8," if $8; print " 9: $9," if $9; print " 10: $10," if $10; print " 11: $11," if $11; print " 12: $12," if $12; print " 13: $13," if $13; print " 14: $14," if $14; print " 15: $15," if $15; print " 16: $16," if $16; print " 17: $17," if $17; print " 18: $18," if $18; print " 19: $19," if $19; print " 20: $20," if $20; print " 21: $21," if $21; print " 22: $22," if $22; print " 23: $23," if $23; print " 24: $24," if $24; print " 25: $25," if $25; print " 26: $26," if $26; print " 27: $27," if $27; print " 28: $28," if $28; print " 29: $29," if $29; print " 30: $30," if $30; print " 31: $31," if $31; print " 32: $32," if $32; print " 33: $33," if $33; print " 34: $34," if $34; print " 35: $35," if $35; print " 36: $36," if $36; print " 37: $37," if $37; print " 38: $38," if $38; print " 39: $39," if $39; print " 40: $40," if $40; print " 41: $41," if $41; print " 42: $42," if $42; print " 43: $43," if $43; print " 44: $44," if $44; print " 45: $45," if $45; print " 46: $46," if $46; print " 47: $47" if $47; print "\n"; 
  }
  #
  my $etmsg1=$1;
  my $http_urilen2=$2 if $2;
  #
     $http_method2=$3 if $3;
     $http_methodnocase2=$4 if $4;
  #
  my $http_uri03=$5 if $5;		# old 5
  my $http_urifast5=$6 if $6;
  my $http_urinocase5=$7 if $7;
     $http_urioffset=$8 if $8;
     $http_uridepth=$9 if $9;
  # distance
  # distance
  #
  my $http_header06=$12 if $12;		# old 9
  # fastpattern
  my $http_headernocase9=$14 if $14;
  # offset/depth
  # offset/depth
  # distance
  # distance
  my $http_headernocase12=$19 if $19;
  # fastpattern
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $http_uri11=$25 if $25;		# old 19
  my $http_urifast19=$26 if $26;
  my $http_urinocase16=$27 if $27;
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $http_uri14=$32 if $32;		# old 24
  my $http_urifast24=$33 if $33;
  my $http_urinocase20=$34 if $34;
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $http_uri17=$39 if $39;		# old 29
  my $http_urifast29=$40 if $40;
  my $http_urinocase23=$41 if $41;
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $pcre_uri20=$46 if $46;		# old 34
  my $metadatacreatedyear=$47 if $47;

  # check what is http_uri best length ?
  my $httpuricourt=0;
  my $http_uri03_length=0;
  my $http_uri11_length=0;
  my $http_uri14_length=0;
  my $http_uri17_length=0;
  $http_uri03_length=length($http_uri03) if $http_uri03;
  $http_uri11_length=length($http_uri11) if $http_uri11;
  $http_uri14_length=length($http_uri14) if $http_uri14;
  $http_uri17_length=length($http_uri17) if $http_uri17;
  if( $http_uri03_length >= $http_uri11_length && $http_uri03_length >= $http_uri14_length && $http_uri03_length >= $http_uri17_length )
  { $httpuricourt=$http_uri03; }
  elsif( $http_uri11_length >= $http_uri03_length && $http_uri11_length >= $http_uri14_length && $http_uri11_length >= $http_uri17_length )
  { $httpuricourt=$http_uri11; $http_urioffset=0; $http_uridepth=0; }
  elsif( $http_uri14_length >= $http_uri03_length && $http_uri14_length >= $http_uri11_length && $http_uri14_length >= $http_uri17_length )
  { $httpuricourt=$http_uri14; $http_urioffset=0; $http_uridepth=0; }
  elsif( $http_uri17_length >= $http_uri03_length && $http_uri17_length >= $http_uri11_length && $http_uri17_length >= $http_uri14_length )
  { $httpuricourt=$http_uri17; $http_urioffset=0; $http_uridepth=0; }

  # need escape special char before compare with pcre
  $http_uri03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri03 && $pcre_uri20; # (
  $http_uri03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri03 && $pcre_uri20; # )
  $http_uri03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri03 && $pcre_uri20; # *
  $http_uri03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri03 && $pcre_uri20; # +
  $http_uri03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri03 && $pcre_uri20; # -
  $http_uri03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri03 && $pcre_uri20; # .
  $http_uri03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri03 && $pcre_uri20; # /
  $http_uri03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri03 && $pcre_uri20; # ?
  $http_uri03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri03 && $pcre_uri20; # [
  $http_uri03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri03 && $pcre_uri20; # ]
  $http_uri03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri03 && $pcre_uri20; # ^
  $http_uri03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri03 && $pcre_uri20; # {
  $http_uri03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri03 && $pcre_uri20; # }
  $http_header06 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header06; # (
  $http_header06 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header06; # )
  $http_header06 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header06; # *
  $http_header06 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header06; # +
  $http_header06 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header06; # -
  $http_header06 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header06; # .
  $http_header06 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header06; # /
  $http_header06 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header06; # ?
  $http_header06 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header06; # [
  $http_header06 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header06; # ]
  #$http_header06 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header06; # ^
  $http_header06 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header06; # {
  $http_header06 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header06; # }
  $http_uri11 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri11 && $pcre_uri20; # (
  $http_uri11 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri11 && $pcre_uri20; # )
  $http_uri11 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri11 && $pcre_uri20; # *
  $http_uri11 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri11 && $pcre_uri20; # +
  $http_uri11 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri11 && $pcre_uri20; # -
  $http_uri11 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri11 && $pcre_uri20; # .
  $http_uri11 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri11 && $pcre_uri20; # /
  $http_uri11 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri11 && $pcre_uri20; # ?
  $http_uri11 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri11 && $pcre_uri20; # [
  $http_uri11 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri11 && $pcre_uri20; # ]
  $http_uri11 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri11 && $pcre_uri20; # ^
  $http_uri11 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri11 && $pcre_uri20; # {
  $http_uri11 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri11 && $pcre_uri20; # }
  $http_uri14 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri14 && $pcre_uri20; # (
  $http_uri14 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri14 && $pcre_uri20; # )
  $http_uri14 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri14 && $pcre_uri20; # *
  $http_uri14 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri14 && $pcre_uri20; # +
  $http_uri14 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri14 && $pcre_uri20; # -
  $http_uri14 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri14 && $pcre_uri20; # .
  $http_uri14 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri14 && $pcre_uri20; # /
  $http_uri14 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri14 && $pcre_uri20; # ?
  $http_uri14 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri14 && $pcre_uri20; # [
  $http_uri14 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri14 && $pcre_uri20; # ]
  $http_uri14 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri14 && $pcre_uri20; # ^
  $http_uri14 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri14 && $pcre_uri20; # {
  $http_uri14 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri14 && $pcre_uri20; # }
  $http_uri17 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri17 && $pcre_uri20; # (
  $http_uri17 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri17 && $pcre_uri20; # )
  $http_uri17 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri17 && $pcre_uri20; # *
  $http_uri17 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri17 && $pcre_uri20; # +
  $http_uri17 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri17 && $pcre_uri20; # -
  $http_uri17 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri17 && $pcre_uri20; # .
  $http_uri17 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri17 && $pcre_uri20; # /
  $http_uri17 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri17 && $pcre_uri20; # ?
  $http_uri17 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri17 && $pcre_uri20; # [
  $http_uri17 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri17 && $pcre_uri20; # ]
  $http_uri17 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri17 && $pcre_uri20; # ^
  $http_uri17 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri17 && $pcre_uri20; # {
  $http_uri17 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri17 && $pcre_uri20; # }
  #$pcre_uri20 =~ s/(?<!\x5C)\x24//g         if $pcre_uri20; # $

  while($http_uri03 && $http_uri03=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri03=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_header06 && $http_header06=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header06=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri11 && $http_uri11=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri11=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri14 && $http_uri14=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri14=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri17 && $http_uri17=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri17=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  # ne pas faire d'echappement sur la pcre ($pcre_uri20)
  my $abc1=0;
  my $httppcreagent=0;
  my $httpagentshort=0;
  my $pcrereferer=0;
  my @tableauuri1;

     if( $http_header06 && $http_header06 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~ s/\QUser-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser-Agent\: \E$/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser-Agent\:\E$/i ) { undef($http_header06) }
                           $http_header06 =~ s/\Q\x0D\x0A\E/\$/i if $http_header06; # http_header, \x0D\x0A
     if( $http_header06 && $http_header06 =~ s/\QReferer\x3A\x20\E/^/i ) { $pcrereferer = $http_header06; undef $http_header06 }
  elsif( $http_header06 && $http_header06 =~ s/\QReferer\x3A \E/^/i ) { $pcrereferer = $http_header06; undef $http_header06 }

  #if( $pcre_uri20 )
  #{
  # $pcre_uri20 =~ s/^\^\\\//\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\\//i;
  # $pcre_uri20 =~ s/^\^\\x2F/\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\x2F/i;
  #}

  # http_user_agent short
  if( $http_header06 )
  {
   $httpagentshort= "$http_header06" if $http_header06;
  }
  while( $httpagentshort =~ /\\x(..)/g )
  {
   my $tempochr=chr(hex("$1"));
   $httpagentshort =~ s/\\x(..)/$tempochr/;
  }
  $httpagentshort =~ s/(?:\\(?!$)(?:x[a-f0-9]{2})?|\^|\$)//g;

  if( $pcre_uri20 && $http_uri03 && $pcre_uri20=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouvé grep3a\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri03 && $http_uri03=~s/\&/\\x26/g && $pcre_uri20=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouvé grep3b\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri03 && $http_uri03=~s/\=/\\x3D/g && $pcre_uri20=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouvé grep3c\n" if $debug1;
  }
  if( $pcre_uri20 && $http_header06 && $pcre_uri20=~/\Q$http_header06\E/i ) {
   undef $http_header06;
   print "ok trouvé grep6a\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_header06 && $http_header06=~s/\&/\\x26/g && $pcre_uri20=~/\Q$http_header06\E/i ) {
   undef $http_header06;
   print "ok trouvé grep6b\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_header06 && $http_header06=~s/\=/\\x3D/g && $pcre_uri20=~/\Q$http_header06\E/i ) {
   undef $http_header06;
   print "ok trouvé grep6c\n" if $debug1;
  }
  if( $pcre_uri20 && $http_uri11 && $pcre_uri20=~/\Q$http_uri11\E/i ) {
   undef $http_uri11;
   print "ok trouvé grep11a\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri11 && $http_uri11=~s/\&/\\x26/g && $pcre_uri20=~/\Q$http_uri11\E/i ) {
   undef $http_uri11;
   print "ok trouvé grep11b\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri11 && $http_uri11=~s/\=/\\x3D/g && $pcre_uri20=~/\Q$http_uri11\E/i ) {
   undef $http_uri11;
   print "ok trouvé grep11c\n" if $debug1;
  }
  if( $pcre_uri20 && $http_uri14 && $pcre_uri20=~/\Q$http_uri14\E/i ) {
   undef $http_uri14;
   print "ok trouvé grep14a\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri14 && $http_uri14=~s/\&/\\x26/g && $pcre_uri20=~/\Q$http_uri14\E/i ) {
   undef $http_uri14;
   print "ok trouvé grep14b\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri14 && $http_uri14=~s/\=/\\x3D/g && $pcre_uri20=~/\Q$http_uri14\E/i ) {
   undef $http_uri14;
   print "ok trouvé grep14c\n" if $debug1;
  }
  if( $pcre_uri20 && $http_uri17 && $pcre_uri20=~/\Q$http_uri17\E/i ) {
   undef $http_uri17;
   print "ok trouvé grep17a\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri17 && $http_uri17=~s/\&/\\x26/g && $pcre_uri20=~/\Q$http_uri17\E/i ) {
   undef $http_uri17;
   print "ok trouvé grep17b\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri17 && $http_uri17=~s/\=/\\x3D/g && $pcre_uri20=~/\Q$http_uri17\E/i ) {
   undef $http_uri17;
   print "ok trouvé grep17c\n" if $debug1;
  }

  # one uri
  #$abc1= "$http_uri03" if $http_uri03 && !$http_uri11 && !$http_uri14 && !$http_uri17 && !$pcre_uri20;
  #$abc1= "$http_uri11" if $http_uri11 && !$http_uri03 && !$http_uri14 && !$http_uri17 && !$pcre_uri20;
  #$abc1= "$http_uri14" if $http_uri14 && !$http_uri03 && !$http_uri11 && !$http_uri17 && !$pcre_uri20;
  #$abc1= "$http_uri17" if $http_uri17 && !$http_uri03 && !$http_uri11 && !$http_uri14 && !$pcre_uri20;
  $abc1= "$pcre_uri20" if $pcre_uri20 && !$http_uri03 && !$http_uri11 && !$http_uri14 && !$http_uri17;

  # one header
  #$httppcreagent= "$http_header06" if $http_header06;

  # two uri
  if( $http_uri03 && $http_uri11 && !$http_uri14 && !$http_uri17 && !$pcre_uri20 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri11 !~ /\\x|^\^|\$$/ )) )
  {
   @tableauuri1 = ( $http_uri03, $http_uri11 ) if $http_uri03 && $http_uri11 && !$http_uri14 && !$http_uri17 && !$pcre_uri20;
   my $tableauuri1index=0;
   foreach( @tableauuri1 )
   {
    $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
    if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
   }
  }
  else
  {
   $abc1= "(?:$http_uri03.*?$http_uri11|$http_uri11.*?$http_uri03)" if $http_uri03 && $http_uri11 && !$http_uri14 && !$http_uri17 && !$pcre_uri20;
  }

  if( $http_uri03 && $http_uri14 && !$http_uri11 && !$http_uri17 && !$pcre_uri20 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri14 !~ /\\x|^\^|\$$/ )) )
  {
   @tableauuri1 = ( $http_uri03, $http_uri14 ) if $http_uri03 && $http_uri14 && !$http_uri11 && !$http_uri17 && !$pcre_uri20;
   my $tableauuri1index=0;
   foreach( @tableauuri1 )
   {
    $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
    if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
   }
  }
  else
  {
   $abc1= "(?:$http_uri03.*?$http_uri14|$http_uri14.*?$http_uri03)" if $http_uri03 && $http_uri14 && !$http_uri11 && !$http_uri17 && !$pcre_uri20;
  }

  if( $http_uri03 && $http_uri17 && !$http_uri11 && !$http_uri14 && !$pcre_uri20 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri17 !~ /\\x|^\^|\$$/ )) )
  {
   @tableauuri1 = ( $http_uri03, $http_uri17 ) if $http_uri03 && $http_uri17 && !$http_uri11 && !$http_uri14 && !$pcre_uri20;
   my $tableauuri1index=0;
   foreach( @tableauuri1 )
   {
    $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
    if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
   }
  }
  else
  {
   $abc1= "(?:$http_uri03.*?$http_uri17|$http_uri17.*?$http_uri03)" if $http_uri03 && $http_uri17 && !$http_uri11 && !$http_uri14 && !$pcre_uri20;
  }

  $abc1= "(?:$http_uri03.*?$pcre_uri20|$pcre_uri20.*?$http_uri03)" if $http_uri03 && $pcre_uri20 && !$http_uri11 && !$http_uri14 && !$http_uri17;

  # three uri
  if( $http_uri03 && $http_uri11 && $http_uri14 && !$http_uri17 && !$pcre_uri20 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri11 !~ /\\x|^\^|\$$/ ) or ( $http_uri14 !~ /\\x|^\^|\$$/ )) )
  {
   @tableauuri1 = ( $http_uri03, $http_uri11, $http_uri14 ) if $http_uri03 && $http_uri11 && $http_uri14 && !$http_uri17 && !$pcre_uri20;
   my $tableauuri1index=0;
   foreach( @tableauuri1 )
   {
    $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
    if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
   }
  }
  else
  {
   $abc1= "(?:$http_uri03.*$http_uri11.*$http_uri14|$http_uri03.*$http_uri14.*$http_uri11|$http_uri14.*$http_uri11.*$http_uri03|$http_uri11.*$http_uri14.*$http_uri03)" if $http_uri03 && $http_uri11 && $http_uri14 && !$http_uri17 && !$pcre_uri20;
  }

  if( $http_uri03 && $http_uri11 && $http_uri17 && !$http_uri14 && !$pcre_uri20 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri11 !~ /\\x|^\^|\$$/ ) or ( $http_uri17 !~ /\\x|^\^|\$$/ )) )
  {
   @tableauuri1 = ( $http_uri03, $http_uri11, $http_uri17 ) if $http_uri03 && $http_uri11 && $http_uri17 && !$http_uri14 && !$pcre_uri20;
   my $tableauuri1index=0;
   foreach( @tableauuri1 )
   {
    $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
    if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
   }
  }
  else
  {
   $abc1= "(?:$http_uri03.*$http_uri11.*$http_uri17|$http_uri03.*$http_uri17.*$http_uri11|$http_uri17.*$http_uri11.*$http_uri03|$http_uri11.*$http_uri17.*$http_uri03)" if $http_uri03 && $http_uri11 && $http_uri17 && !$http_uri14 && !$pcre_uri20;
  }

  $abc1= "(?:$http_uri03.*$http_uri11.*$pcre_uri20|$http_uri03.*$pcre_uri20.*$http_uri11|$pcre_uri20.*$http_uri11.*$http_uri03|$http_uri11.*$pcre_uri20.*$http_uri03)" if $http_uri03 && $http_uri11 && $pcre_uri20 && !$http_uri14 && !$http_uri17;

  # four uri
  $abc1= "(?:$http_uri03.*$http_uri11.*$http_uri14.*$pcre_uri20|$http_uri03.*$http_uri11.*$pcre_uri20.*$http_uri14|$http_uri03.*$http_uri14.*$http_uri11.*$pcre_uri20|$http_uri03.*$http_uri14.*$pcre_uri20.*$http_uri11|$http_uri11.*$http_uri14.*$pcre_uri20.*$http_uri03|$http_uri11.*$http_uri14.*$http_uri03.*$pcre_uri20|$http_uri11.*$http_uri03.*$http_uri14.*$pcre_uri20|$http_uri11.*$http_uri03.*$pcre_uri20.*$http_uri14|$http_uri14.*$http_uri03.*$http_uri11.*$pcre_uri20|$http_uri14.*$http_uri03.*$pcre_uri20.*$http_uri11|$http_uri14.*$http_uri11.*$pcre_uri20.*$http_uri03|$http_uri14.*$http_uri11.*$http_uri03.*$pcre_uri20|$pcre_uri20.*$http_uri03.*$http_uri11.*$http_uri14|$pcre_uri20.*$http_uri03.*$http_uri14.*$http_uri11|$pcre_uri20.*$http_uri14.*$http_uri03.*$http_uri11|$pcre_uri20.*$http_uri14.*$http_uri11.*$http_uri03)" if $http_uri03 && $http_uri11 && $http_uri14 && $pcre_uri20 && !$http_uri17;

  # uri:
  my $abc1_nocase=0;
     $abc1_nocase=$http_urifast5    if $http_urifast5;
     $abc1_nocase=$http_urinocase5  if $http_urinocase5;
     $abc1_nocase=$http_urifast19   if $http_urifast19;
     $abc1_nocase=$http_urinocase16 if $http_urinocase16;
     $abc1_nocase=$http_urifast24   if $http_urifast24;
     $abc1_nocase=$http_urinocase20 if $http_urinocase20;
     $abc1_nocase=$http_urifast29   if $http_urifast29;
     $abc1_nocase=$http_urinocase23 if $http_urinocase23;
  # header:
  my $httppcreagent_nocase=0;
     $httppcreagent_nocase=$http_headernocase9 if $http_headernocase9;
     $httppcreagent_nocase=$http_headernocase12 if $http_headernocase12;

  # check again if pcre need escape
  $httppcreagent =~ s/(?<!\x5C)\x28/\x5C\x28/g if $httppcreagent; # (
  $httppcreagent =~ s/(?<!\x5C)\x29/\x5C\x29/g if $httppcreagent; # )
  $httppcreagent =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $httppcreagent; # *
  $httppcreagent =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $httppcreagent; # +
  $httppcreagent =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $httppcreagent; # -
  $httppcreagent =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $httppcreagent; # .
  $httppcreagent =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $httppcreagent; # /
  $httppcreagent =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $httppcreagent; # ?
  $httppcreagent =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $httppcreagent; # [
  $httppcreagent =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $httppcreagent; # ]
  #$httppcreagent =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $httppcreagent; # ^
  $httppcreagent =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $httppcreagent; # {
  $httppcreagent =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $httppcreagent; # }

 if( !@year2 || grep(/$metadatacreatedyear/, @year2) )
 {
  print "httpuricourt2: $etmsg1, ".lc($httpuricourt) if $debug1 && $httpuricourt; print ", depth: $http_uridepth" if $debug1 && $httpuricourt && $http_uridepth; print ", offset: $http_urioffset" if $debug1 && $httpuricourt && $http_urioffset; print "\n" if $debug1 && $httpuricourt;
  print "httpurilong2: $etmsg1, @tableauuri1\n" if $debug1 && @tableauuri1;
  print "tableaupcreuri2: $etmsg1, $abc1, $abc1_nocase\n" if $debug1 && $abc1;
  print "tableaupcreagent2: $etmsg1, $httppcreagent, $httppcreagent_nocase\n" if $debug1 && $httppcreagent;
  print "httpagentshort2: $etmsg1, ".lc($httpagentshort)."\n" if $debug1 && $httpagentshort;
  print "tableauhttpmethod2: $etmsg1, $http_method2, $http_methodnocase2\n" if $debug1 && $http_method2;
  print "tableaupcrereferer2: $etmsg1, $pcrereferer\n" if $debug1 && $pcrereferer;
  print "http_urilen2: $etmsg1, $http_urilen2\n" if $debug1 && $http_urilen2;
  print "metadata_created_year2: $etmsg1, $metadatacreatedyear\n" if $debug1 && $metadatacreatedyear;

  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt), $http_uridepth, $http_urioffset ] if $httpuricourt && $http_uridepth && $http_urioffset;
  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt), $http_uridepth ] if $httpuricourt && $http_uridepth && !$http_urioffset;
  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt) ] if $httpuricourt && !$http_uridepth && !$http_urioffset;
  #
  $hash{$etmsg1}{httpagentshort} = [ lc($httpagentshort) ] if $httpagentshort;
  $hash{$etmsg1}{httpmethod} = [ $http_method2, $http_methodnocase2 ] if $http_method2;
  $hash{$etmsg1}{pcrereferer} = [ $pcrereferer ] if $pcrereferer;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{pcreagent} = [ $httppcreagent, $httppcreagent_nocase ] if $httppcreagent;
  $hash{$etmsg1}{httpurilong} = [ @tableauuri1 ] if @tableauuri1;
  $hash{$etmsg1}{httpurilen} = [ $http_urilen2 ] if $http_urilen2;
 }

  next;
 }

 # begin http_uri followed by a http_header
# elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flowbits1)?(?:$flow1)?(?:$httpmethod)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreuri)?(?:$extracontentoptions)?$referencesidrev$/ )
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flowbits1)?(?:$flow1)?(?:$httpmethod)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreuri)?(?:$extracontentoptions)?$referencesidrev[^\n]*$createdat/ )
 {
  my $http_method3=0;
  my $http_methodnocase3=0;
  my $http_urioffset=0;
  my $http_uridepth=0;
  #
  if( $debug1 ){
   print "brut3: $_\n"; print "here3: 1: $1," if $1; print " 2: $2," if $2; print " 3: $3," if $3; print " 4: $4," if $4; print " 5: $5," if $5; print " 6: $6," if $6; print " 7: $7," if $7; print " 8: $8," if $8; print " 9: $9," if $9; print " 10: $10," if $10; print " 11: $11," if $11; print " 12: $12," if $12; print " 13: $13," if $13; print " 14: $14," if $14; print " 15: $15," if $15; print " 16: $16," if $16; print " 17: $17," if $17; print " 18: $18," if $18; print " 19: $19," if $19; print " 20: $20," if $20; print " 21: $21," if $21; print " 22: $22," if $22; print " 23: $23," if $23; print " 24: $24," if $24; print " 25: $25," if $25; print " 26: $26," if $26; print " 27: $27," if $27; print " 28: $28," if $28; print " 29: $29," if $29; print " 30: $30," if $30; print " 31: $31," if $31; print " 32: $32," if $32; print " 33: $33," if $33; print " 34: $34," if $34; print " 35: $35," if $35; print " 36: $36," if $36; print " 37: $37," if $37; print " 38: $38," if $38; print " 39: $39," if $39; print " 40: $40," if $40; print " 41: $41," if $41; print " 42: $42," if $42; print " 43: $43," if $43; print " 44: $44," if $44; print " 45: $45," if $45; print " 46: $46," if $46; print " 47: $47," if $47; print " 48: $48," if $48; print " 49: $49," if $49; print " 50: $50," if $50; print " 51: $51," if $51; print " 52: $52," if $52; print " 53: $53," if $53; print " 54: $54," if $54; print " 55: $55," if $55; print " 56: $56," if $56; print " 57: $57" if $57; print "\n";
  }
  #
  my $etmsg1=$1;
  #
     $http_method3=$2 if $2;
     $http_methodnocase3=$3 if $3;
  #
  my $http_uri03=$4 if $4;			# old 4
  my $http_urifast5=$5 if $5;
  my $http_urinocase5=$6 if $6;
     $http_urioffset=$7 if $7;
     $http_uridepth=$8 if $8;
  # distance
  # distance
  my $http_urifast9=$11 if $11;
  my $http_urinocase8=$12 if $12;
     $http_urioffset=$13 if $13;
     $http_uridepth=$14 if $14;
  # distance
  # distance
  #
  my $http_header08=$17 if $17;			# old 13
  my $http_headerfast14=$18 if $18;
  my $http_headernocase12=$19 if $19;
  # offset/depth
  # offset/depth
  # distance
  # distance
  my $http_headerfast18=$24 if $24;
  my $http_headernocase15=$25 if $25;
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $http_uri13=$30 if $30;			# old 22
  my $http_urifast23=$31 if $31;
  my $http_urinocase19=$32 if $32;
  # offset/depth
  # offset/depth
  my $distance14=$35 if defined($35);
  my $distance15=$36 if defined($36);
  my $http_urifast27=$37 if $37;
  my $http_urinocase22=$38 if $38;
  # offset/depth
  # offset/depth
  my $distance16=$41 if defined($41);
  my $distance17=$42 if defined($42);
  #
  my $http_header18=$43 if $43;			# old 31
  my $http_headerfast32=$44 if $44;
  my $http_headernocase26=$45 if $45;
  # offset/depth
  # offset/depth
  my $distance34=$48 if defined($48);
  my $distance35=$49 if defined($49);
  my $http_headerfast36=$50 if $50;
  my $http_headernocase29=$51 if $51;
  # offset/depth
  # offset/depth
  my $distance38=$54 if defined($54);
  my $distance39=$55 if defined($55);
  #
  my $pcre_uri23=$56 if $56;			# old 40
  my $metadatacreatedyear=$57 if $57;

  # check what is http_uri best length ?
  my $httpuricourt=0;
  my $http_uri03_length=0;
  my $http_uri13_length=0;
  $http_uri03_length=length($http_uri03) if $http_uri03;
  $http_uri13_length=length($http_uri13) if $http_uri13;
  if( $http_uri03_length >= $http_uri13_length )
  { $httpuricourt=$http_uri03; }
  elsif( $http_uri13_length >= $http_uri03_length )
  { $httpuricourt=$http_uri13; $http_urioffset=0; $http_uridepth=0; }

  # need escape special char before compare with pcre
  $http_uri03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri03 && $pcre_uri23; # (
  $http_uri03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri03 && $pcre_uri23; # )
  $http_uri03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri03 && $pcre_uri23; # *
  $http_uri03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri03 && $pcre_uri23; # +
  $http_uri03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri03 && $pcre_uri23; # -
  $http_uri03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri03 && $pcre_uri23; # .
  $http_uri03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri03 && $pcre_uri23; # /
  $http_uri03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri03 && $pcre_uri23; # ?
  $http_uri03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri03 && $pcre_uri23; # [
  $http_uri03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri03 && $pcre_uri23; # ]
  $http_uri03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri03 && $pcre_uri23; # ^
  $http_uri03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri03 && $pcre_uri23; # {
  $http_uri03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri03 && $pcre_uri23; # }
  $http_header08 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header08; # (
  $http_header08 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header08; # )
  $http_header08 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header08; # *
  $http_header08 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header08; # +
  $http_header08 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header08; # -
  $http_header08 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header08; # .
  $http_header08 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header08; # /
  $http_header08 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header08; # ?
  $http_header08 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header08; # [
  $http_header08 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header08; # ]
  #$http_header08 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header08; # ^
  $http_header08 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header08; # {
  $http_header08 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header08; # }
  $http_uri13 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri13 && $pcre_uri23; # (
  $http_uri13 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri13 && $pcre_uri23; # )
  $http_uri13 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri13 && $pcre_uri23; # *
  $http_uri13 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri13 && $pcre_uri23; # +
  $http_uri13 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri13 && $pcre_uri23; # -
  $http_uri13 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri13 && $pcre_uri23; # .
  $http_uri13 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri13 && $pcre_uri23; # /
  $http_uri13 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri13 && $pcre_uri23; # ?
  $http_uri13 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri13 && $pcre_uri23; # [
  $http_uri13 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri13 && $pcre_uri23; # ]
  $http_uri13 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri13 && $pcre_uri23; # ^
  $http_uri13 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri13 && $pcre_uri23; # {
  $http_uri13 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri13 && $pcre_uri23; # }
  $http_header18 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header18; # (
  $http_header18 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header18; # )
  $http_header18 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header18; # *
  $http_header18 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header18; # +
  $http_header18 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header18; # -
  $http_header18 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header18; # .
  $http_header18 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header18; # /
  $http_header18 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header18; # ?
  $http_header18 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header18; # [
  $http_header18 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header18; # ]
  #$http_header18 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header18; # ^
  $http_header18 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header18; # {
  $http_header18 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header18; # }
  #$pcre_uri23 =~ s/(?<!\x5C)\x24//g         if $pcre_uri23; # $

#perl -e '$abc1="1|20 21|2|22 24|3";while($abc1=~/(?<!\x5C)\|(.*?)\|/g){$toto1=$1;print "abc1:$abc1\ntoto1:$toto1\n";$toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g; print "$toto1\n"; $abc1=~s/(?<!\x5C)\|.*?\|/$toto1/}; print "final:$abc1\n"'
  while($http_uri03 && $http_uri03=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri03=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_header08 && $http_header08=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header08=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri13 && $http_uri13=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri13=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
   while($http_header18 && $http_header18=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header18=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  # ne pas faire d'echappement sur la pcre ($pcre_uri23)
  my $abc1=0;
  my $httppcreagent=0;
  my $httpagentshort=0;
  my $pcrereferer=0;
  my @tableauuri1;

     if( $http_header08 && $http_header08 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~ s/\QUser-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser-Agent\: \E$/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser-Agent\:\E$/i ) { undef($http_header08) }
                           $http_header08 =~ s/\Q\x0D\x0A\E/\$/i if $http_header08; # http_header, \x0D\x0A
     if( $http_header18 && $http_header18 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~ s/\QUser-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser-Agent\: \E$/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser-Agent\:\E$/i ) { undef($http_header18) }
                           $http_header18 =~ s/\Q\x0D\x0A\E/\$/i if $http_header18; # http_header, \x0D\x0A
     if( $http_header08 && $http_header08 =~ s/\QReferer\x3A\x20\E/^/i ) { $pcrereferer = $http_header08; undef $http_header08 }
  elsif( $http_header08 && $http_header08 =~ s/\QReferer\x3A \E/^/i ) { $pcrereferer = $http_header08; undef $http_header08 }
     if( $http_header18 && $http_header18 =~ s/\QReferer\x3A\x20\E/^/i ) { $pcrereferer = $http_header18; undef $http_header18 }
  elsif( $http_header18 && $http_header18 =~ s/\QReferer\x3A \E/^/i ) { $pcrereferer = $http_header18; undef $http_header18 }

  #if( $pcre_uri23 )
  #{
  # $pcre_uri23 =~ s/^\^\\\//\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\\//i;
  # $pcre_uri23 =~ s/^\^\\x2F/\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\x2F/i;
  #}

  # http_user_agent short
  if( $http_header08 && $http_header18 && length($http_header08) >= length($http_header18) )
  {
   $httpagentshort= "$http_header08" if $http_header08;
  }
  elsif( $http_header08 && $http_header18 && length($http_header18) >= length($http_header08) )
  {
   $httpagentshort= "$http_header18" if $http_header18;
  }
  elsif( $http_header08 )
  {
   $httpagentshort= "$http_header08" if $http_header08;
  }
  elsif( $http_header18 )
  {
   $httpagentshort= "$http_header18" if $http_header18;
  }
  while( $httpagentshort =~ /\\x(..)/g )
  {
   my $tempochr=chr(hex("$1"));
   $httpagentshort =~ s/\\x(..)/$tempochr/;
  }
  $httpagentshort =~ s/(?:\\(?!$)(?:x[a-f0-9]{2})?|\^|\$)//g;

  if( $pcre_uri23 && $http_uri03 && $pcre_uri23=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouvé grep3a\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_uri03 && $http_uri03=~s/\&/\\x26/g && $pcre_uri23=~/\Q$http_uri03\E/i ) {
   undef $http_uri03; 
   print "ok trouvé grep3b\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_uri03 && $http_uri03=~s/\=/\\x3D/g && $pcre_uri23=~/\Q$http_uri03\E/i ) {
   undef $http_uri03; 
   print "ok trouvé grep3c\n" if $debug1;
  }
  if( $pcre_uri23 && $http_header08 && $pcre_uri23=~/\Q$http_header08\E/i ) {
   undef $http_header08; 
   print "ok trouvé grep8a\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_header08 && $http_header08=~s/\&/\\x26/g && $pcre_uri23=~/\Q$http_header08\E/i ) {
   undef $http_header08;
   print "ok trouvé grep8b\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_header08 && $http_header08=~s/\=/\\x3D/g && $pcre_uri23=~/\Q$http_header08\E/i ) {
   undef $http_header08;
   print "ok trouvé grep8c\n" if $debug1;
  }
  if( $pcre_uri23 && $http_uri13 && $pcre_uri23=~/\Q$http_uri13\E/i ) {
   undef $http_uri13;
   print "ok trouvé grep13a\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_uri13 && $http_uri13=~s/\&/\\x26/g && $pcre_uri23=~/\Q$http_uri13\E/i ) {
   undef $http_uri13;
   print "ok trouvé grep13b\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_uri13 && $http_uri13=~s/\=/\\x3D/g && $pcre_uri23=~/\Q$http_uri13\E/i ) {
   undef $http_uri13;
   print "ok trouvé grep13c\n" if $debug1;
  }
  if( $pcre_uri23 && $http_header18 && $pcre_uri23=~/\Q$http_header18\E/i ) {
   undef $http_header18;
   print "ok trouvé grep18a\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_header18 && $http_header18=~s/\&/\\x26/g && $pcre_uri23=~/\Q$http_header18\E/i ) {
   undef $http_header18;
   print "ok trouvé grep18b\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_header18 && $http_header18=~s/\=/\\x3D/g && $pcre_uri23=~/\Q$http_header18\E/i ) {
   undef $http_header18;
   print "ok trouvé grep18c\n" if $debug1;
  }

  # check again if header content need escape
  $http_header08 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header08; # (
  $http_header08 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header08; # )
  $http_header08 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header08; # *
  $http_header08 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header08; # +
  $http_header08 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header08; # -
  $http_header08 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header08; # .
  $http_header08 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header08; # /
  $http_header08 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header08; # ?
  $http_header08 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header08; # [
  $http_header08 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header08; # ]
  #$http_header08 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header08; # ^
  $http_header08 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header08; # {
  $http_header08 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header08; # }
  $http_header18 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header18; # (
  $http_header18 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header18; # )
  $http_header18 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header18; # *
  $http_header18 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header18; # +
  $http_header18 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header18; # -
  $http_header18 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header18; # .
  $http_header18 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header18; # /
  $http_header18 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header18; # ?
  $http_header18 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header18; # [
  $http_header18 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header18; # ]
  #$http_header18 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header18; # ^
  $http_header18 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header18; # {
  $http_header18 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header18; # }

  # one uri
  #$abc1= "$http_uri03" if $http_uri03 && !$http_uri13 && !$pcre_uri23;
  #$abc1= "$http_uri13" if $http_uri13 && !$http_uri03 && !$pcre_uri23;
  $abc1= "$pcre_uri23" if $pcre_uri23 && !$http_uri03 && !$http_uri13;

  # one header
  #$httppcreagent= "$http_header08" if $http_header08 && !$http_header18;
  #$httppcreagent= "$http_header18" if $http_header18 && !$http_header08;

  # two header
  $httppcreagent= "(?:$http_header08.*?$http_header18|$http_header18.*?$http_header08)" if $http_header08 && $http_header18;

  # two uri
  if( $http_uri03 && $http_uri13 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri13 !~ /\\x|^\^|\$$/ )) )
  {
   @tableauuri1 = ( $http_uri03, $http_uri13 ) if $http_uri03 && $http_uri13 && !$pcre_uri23;
   my $tableauuri1index=0;
   foreach( @tableauuri1 )
   {
    $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
    if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
   }
  }
  else
  {
   $abc1= "(?:$http_uri03.*?$http_uri13|$http_uri13.*?$http_uri03)" if $http_uri03 && $http_uri13 && !$pcre_uri23;
  }

  $abc1= "(?:$http_uri03.*?$pcre_uri23|$pcre_uri23.*?$http_uri03)" if $http_uri03 && $pcre_uri23 && !$http_uri13;

  # three uri
  $abc1= "(?:$http_uri03.*$http_uri13.*$pcre_uri23|$http_uri03.*$pcre_uri23.*$http_uri13|$pcre_uri23.*$http_uri13.*$http_uri03|$http_uri13.*$pcre_uri23.*$http_uri03)" if $http_uri03 && $http_uri13 && $pcre_uri23;

  # uri:
  my $abc1_nocase=0;
     $abc1_nocase=$http_urifast5    if $http_urifast5;
     $abc1_nocase=$http_urinocase5  if $http_urinocase5;
     $abc1_nocase=$http_urifast9    if $http_urifast9;
     $abc1_nocase=$http_urinocase8  if $http_urinocase8;
     $abc1_nocase=$http_urifast23   if $http_urifast23;
     $abc1_nocase=$http_urinocase19 if $http_urinocase19;
     $abc1_nocase=$http_urifast27   if $http_urifast27;
     $abc1_nocase=$http_urinocase22 if $http_urinocase22;
  # header:
  my $httppcreagent_nocase=0;
     $httppcreagent_nocase=$http_headerfast14   if $http_headerfast14;
     $httppcreagent_nocase=$http_headernocase12 if $http_headernocase12;
     $httppcreagent_nocase=$http_headerfast18   if $http_headerfast18;
     $httppcreagent_nocase=$http_headernocase15 if $http_headernocase15;
     $httppcreagent_nocase=$http_headerfast32   if $http_headerfast32;
     $httppcreagent_nocase=$http_headernocase26 if $http_headernocase26;
     $httppcreagent_nocase=$http_headerfast36   if $http_headerfast36;
     $httppcreagent_nocase=$http_headernocase29 if $http_headernocase29;

 if( !@year2 || grep(/$metadatacreatedyear/, @year2) )
 {
  print "httpuricourt3: $etmsg1, ".lc($httpuricourt) if $debug1 && $httpuricourt; print ", depth: $http_uridepth" if $debug1 && $httpuricourt && $http_uridepth; print ", offset: $http_urioffset" if $debug1 && $httpuricourt && $http_urioffset; print "\n" if $debug1 && $httpuricourt;
  print "httpurilong3: $etmsg1, @tableauuri1\n" if $debug1 && @tableauuri1;
  print "tableaupcreuri3: $etmsg1, $abc1, $abc1_nocase\n" if $debug1 && $abc1;
  print "tableaupcreagent3: $etmsg1, $httppcreagent, $httppcreagent_nocase\n" if $debug1 && $httppcreagent;
  print "httpagentshort3: $etmsg1, ".lc($httpagentshort)."\n" if $debug1 && $httpagentshort;
  print "tableauhttpmethod3: $etmsg1, $http_method3, $http_methodnocase3\n" if $debug1 && $http_method3;
  print "tableaupcrereferer3: $etmsg1, $pcrereferer\n" if $debug1 && $pcrereferer;
  print "metadata_created_year3: $etmsg1, $metadatacreatedyear\n" if $debug1 && $metadatacreatedyear;

  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt), $http_uridepth, $http_urioffset ] if $httpuricourt && $http_uridepth && $http_urioffset;
  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt), $http_uridepth ] if $httpuricourt && $http_uridepth && !$http_urioffset;
  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt) ] if $httpuricourt && !$http_uridepth && !$http_urioffset;
  #
  $hash{$etmsg1}{httpagentshort} = [ lc($httpagentshort) ] if $httpagentshort;
  $hash{$etmsg1}{httpmethod} = [ $http_method3, $http_methodnocase3 ] if $http_method3;
  $hash{$etmsg1}{pcrereferer} = [ $pcrereferer ] if $pcrereferer;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{pcreagent} = [ $httppcreagent, $httppcreagent_nocase ] if $httppcreagent;
  $hash{$etmsg1}{httpurilong} = [ @tableauuri1 ] if @tableauuri1;
 }

  next;
 }

 # begin http_header
# elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$urilen1)?(?:$httpmethod)?(?:$negateuricontent1)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreuri)?(?:$pcreagent)?(?:$extracontentoptions)?$referencesidrev$/ )
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$urilen1)?(?:$httpmethod)?(?:$negateuricontent1)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreuri)?(?:$pcreagent)?(?:$extracontentoptions)?$referencesidrev[^\n]*$createdat/ )
 {
  my $http_method4=0;
  my $http_methodnocase4=0;
  my $http_urioffset=0;
  my $http_uridepth=0;
  #
  if( $debug1 ){
   print "brut4: $_\n"; print "here4: 1: $1," if $1; print " 2: $2," if $2; print " 3: $3," if $3; print " 4: $4," if $4; print " 5: $5," if $5; print " 6: $6," if $6; print " 7: $7," if $7; print " 8: $8," if $8; print " 9: $9," if $9; print " 10: $10," if $10; print " 11: $11," if $11; print " 12: $12," if $12; print " 13: $13," if $13; print " 14: $14," if $14; print " 15: $15," if $15; print " 16: $16," if $16; print " 17: $17," if $17; print " 18: $18," if $18; print " 19: $19," if $19; print " 20: $20," if $20; print " 21: $21," if $21; print " 22: $22," if $22; print " 23: $23," if $23; print " 24: $24," if $24; print " 25: $25," if $25; print " 26: $26," if $26; print " 27: $27," if $27; print " 28: $28," if $28; print " 29: $29," if $29; print " 30: $30," if $30; print " 31: $31," if $31; print " 32: $32," if $32; print " 33: $33," if $33; print " 34: $34," if $34; print " 35: $35," if $35; print " 36: $36," if $36; print " 37: $37," if $37; print " 38: $38," if $38; print " 39: $39," if $39; print " 40: $40," if $40; print " 41: $41," if $41; print " 42: $42," if $42; print " 43: $43," if $43; print " 44: $44," if $44; print " 45: $45," if $45; print " 46: $46," if $46; print " 47: $47," if $47; print " 48: $48," if $48; print " 49: $49," if $49; print " 50: $50," if $50; print " 51: $51," if $51; print " 52: $52," if $52; print " 53: $53," if $53; print " 54: $54," if $54; print " 55: $55," if $55; print " 56: $56," if $56; print " 57: $57," if $57; print " 58: $58," if $58; print " 59: $59," if $59; print " 60: $60," if $60; print " 61: $61," if $61; print " 62: $62," if $62; print " 63: $63," if $63; print " 64: $64," if $64; print " 65: $65," if $65; print " 66: $66," if $66; print " 67: $67," if $67; print " 68: $68," if $68; print " 69: $69," if $69; print " 70: $70," if $70; print " 71: $71," if $71; print " 72: $72," if $72; print " 73: $73," if $73; print " 74: $74," if $74; print " 75: $75," if $75; print " 76: $76," if $76; print " 77: $77," if $77; print " 78: $78," if $78; print " 79: $79," if $79; print " 80: $80," if $80; print " 81: $81," if $81; print " 82: $82," if $82; print " 83: $83," if $83; print " 84: $84," if $84; print " 85: $85" if $85; print "\n";
  }
  #
  my $etmsg1=$1;
  my $http_urilen4=$2 if $2;
  #
     $http_method4=$3 if $3;
     $http_methodnocase4=$4 if $4;
  #
  my $http_header03=$5 if $5;		# old 5
  my $http_headerfast5=$6 if $6;
  my $http_headernocase5=$7 if $7;
  # offset/depth
  # offset/depth
  # distance
  # distance
  my $http_headerfast9=$12 if $12;
  my $http_headernocase8=$13 if $13;
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $http_uri08=$18 if $18;		# old 14
  my $http_urifast14=$19 if $19;
  my $http_urinocase12=$20 if $20;
     $http_urioffset=$21 if $21;
     $http_uridepth=$22 if $22;
  # distance
  # distance
  my $http_urifast18=$25 if $25;
  my $http_urinocase15=$26 if $26;
     $http_urioffset=$27 if $27;
     $http_uridepth=$28 if $28;
  # distance
  # distance
  #
  my $http_header13=$31 if $31;		# old 23
  my $http_headerfast23=$32 if $32;
  my $http_headernocase19=$33 if $33;
  # offset/depth
  # offset/depth
  my $distance14=$36 if defined($36);
  my $distance15=$37 if defined($37);
  my $http_headerfast27=$38 if $38;
  my $http_headernocase22=$39 if $39;
  # offset/depth
  # offset/depth
  my $distance16=$42 if defined($42);
  my $distance17=$43 if defined($43);
  #
  my $http_uri18=$44 if $44;		# old 32
  my $http_urifast32=$45 if $45;
  my $http_urinocase25=$46 if $46;
  # offset/depth
  # offset/depth
  my $distance19=$49 if defined($49);
  my $distance20=$50 if defined($50);
  my $http_urifast36=$51 if $51;
  my $http_urinocase28=$52 if $52;
  # offset/depth
  # offset/depth
  my $distance21=$55 if defined($55);
  my $distance22=$56 if defined($56);
  #
  my $http_header23=$57 if $57;		# old 41
  my $http_headerfast41=$58 if $58;
  my $http_headernocase32=$59 if $59;
  # offset/depth
  # offset/depth
  my $distance24=$62 if defined($62);
  my $distance25=$63 if defined($63);
  my $http_headerfast45=$64 if $64;
  my $http_headernocase35=$65 if $65;
  # offset/depth
  # offset/depth
  my $distance26=$68 if defined($68);
  my $distance27=$69 if defined($69);
  #
  my $http_uri28=$70 if $70;		# old 50
  my $http_urifast50=$71 if $71;
  my $http_urinocase39=$72 if $72;
  # offset/depth
  # offset/depth
  my $distance29=$75 if defined($75);
  my $distance30=$76 if defined($76);
  my $http_urifast54=$77 if $77;
  my $http_urinocase42=$78 if $78;
  # offset/depth
  # offset/depth
  my $distance31=$81 if defined($81);
  my $distance32=$82 if defined($82);
  #
  my $pcre_uri33=$83 if $83;		# old 59
  #
  my $pcre_agent34=$84 if $84;		# old 60
  my $metadatacreatedyear=$85 if $85;

  # check what is http_uri best length ?
  my $httpuricourt=0;
  my $http_uri08_length=0;
  my $http_uri18_length=0;
  my $http_uri28_length=0;
  $http_uri08_length=length($http_uri08) if $http_uri08;
  $http_uri18_length=length($http_uri18) if $http_uri18;
  $http_uri28_length=length($http_uri28) if $http_uri28;
  if( $http_uri08_length >= $http_uri18_length && $http_uri08_length >= $http_uri28_length )
  { $httpuricourt=$http_uri08; }
  elsif( $http_uri18_length >= $http_uri08_length && $http_uri18_length >= $http_uri28_length )
  { $httpuricourt=$http_uri18; $http_urioffset=0; $http_uridepth=0; }
  elsif( $http_uri28_length >= $http_uri08_length && $http_uri28_length >= $http_uri18_length )
  { $httpuricourt=$http_uri28; $http_urioffset=0; $http_uridepth=0; }

  # need escape special char before compare with pcre
  $http_header03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header03 && $pcre_agent34; # (
  $http_header03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header03 && $pcre_agent34; # )
  $http_header03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header03 && $pcre_agent34; # *
  $http_header03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header03 && $pcre_agent34; # +
  $http_header03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header03 && $pcre_agent34; # -
  $http_header03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header03 && $pcre_agent34; # .
  $http_header03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header03 && $pcre_agent34; # /
  $http_header03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header03 && $pcre_agent34; # ?
  $http_header03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header03 && $pcre_agent34; # [
  $http_header03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header03 && $pcre_agent34; # ]
  #$http_header03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header03 && $pcre_agent34; # ^
  $http_header03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header03 && $pcre_agent34; # {
  $http_header03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header03 && $pcre_agent34; # }
  $http_uri08 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri08 && $pcre_uri33; # (
  $http_uri08 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri08 && $pcre_uri33; # )
  $http_uri08 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri08 && $pcre_uri33; # *
  $http_uri08 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri08 && $pcre_uri33; # +
  $http_uri08 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri08 && $pcre_uri33; # -
  $http_uri08 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri08 && $pcre_uri33; # .
  $http_uri08 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri08 && $pcre_uri33; # /
  $http_uri08 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri08 && $pcre_uri33; # ?
  $http_uri08 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri08 && $pcre_uri33; # [
  $http_uri08 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri08 && $pcre_uri33; # ]
  $http_uri08 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri08 && $pcre_uri33; # ^
  $http_uri08 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri08 && $pcre_uri33; # {
  $http_uri08 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri08 && $pcre_uri33; # }
  $http_header13 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header13 && $pcre_agent34; # (
  $http_header13 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header13 && $pcre_agent34; # )
  $http_header13 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header13 && $pcre_agent34; # *
  $http_header13 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header13 && $pcre_agent34; # +
  $http_header13 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header13 && $pcre_agent34; # -
  $http_header13 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header13 && $pcre_agent34; # .
  $http_header13 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header13 && $pcre_agent34; # /
  $http_header13 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header13 && $pcre_agent34; # ?
  $http_header13 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header13 && $pcre_agent34; # [
  $http_header13 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header13 && $pcre_agent34; # ]
  #$http_header13 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header13 && $pcre_agent34; # ^
  $http_header13 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header13 && $pcre_agent34; # {
  $http_header13 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header13 && $pcre_agent34; # }
  $http_uri18 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri18 && $pcre_uri33; # (
  $http_uri18 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri18 && $pcre_uri33; # )
  $http_uri18 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri18 && $pcre_uri33; # *
  $http_uri18 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri18 && $pcre_uri33; # +
  $http_uri18 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri18 && $pcre_uri33; # -
  $http_uri18 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri18 && $pcre_uri33; # .
  $http_uri18 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri18 && $pcre_uri33; # /
  $http_uri18 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri18 && $pcre_uri33; # ?
  $http_uri18 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri18 && $pcre_uri33; # [
  $http_uri18 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri18 && $pcre_uri33; # ]
  $http_uri18 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri18 && $pcre_uri33; # ^
  $http_uri18 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri18 && $pcre_uri33; # {
  $http_uri18 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri18 && $pcre_uri33; # }
  $http_header23 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header23 && $pcre_agent34; # (
  $http_header23 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header23 && $pcre_agent34; # )
  $http_header23 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header23 && $pcre_agent34; # *
  $http_header23 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header23 && $pcre_agent34; # +
  $http_header23 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header23 && $pcre_agent34; # -
  $http_header23 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header23 && $pcre_agent34; # .
  $http_header23 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header23 && $pcre_agent34; # /
  $http_header23 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header23 && $pcre_agent34; # ?
  $http_header23 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header23 && $pcre_agent34; # [
  $http_header23 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header23 && $pcre_agent34; # ]
  #$http_header23 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header23 && $pcre_agent34; # ^
  $http_header23 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header23 && $pcre_agent34; # {
  $http_header23 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header23 && $pcre_agent34; # }
  $http_uri28 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri28 && $pcre_uri33; # (
  $http_uri28 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri28 && $pcre_uri33; # )
  $http_uri28 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri28 && $pcre_uri33; # *
  $http_uri28 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri28 && $pcre_uri33; # +
  $http_uri28 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri28 && $pcre_uri33; # -
  $http_uri28 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri28 && $pcre_uri33; # .
  $http_uri28 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri28 && $pcre_uri33; # /
  $http_uri28 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri28 && $pcre_uri33; # ?
  $http_uri28 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri28 && $pcre_uri33; # [
  $http_uri28 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri28 && $pcre_uri33; # ]
  $http_uri28 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri28 && $pcre_uri33; # ^
  $http_uri28 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri28 && $pcre_uri33; # {
  $http_uri28 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri28 && $pcre_uri33; # }
  #$pcre_uri33 =~ s/(?<!\x5C)\x24//g         if $pcre_uri33; # $
  #$pcre_agent34 =~ s/(?<!\x5C)\x24//g         if $pcre_agent34; # $

#perl -e '$abc1="1|20 21|2|22 24|3";while($abc1=~/(?<!\x5C)\|(.*?)\|/g){$toto1=$1;print "abc1:$abc1\ntoto1:$toto1\n";$toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g; print "$toto1\n"; $abc1=~s/(?<!\x5C)\|.*?\|/$toto1/}; print "final:$abc1\n"'
  while($http_header03 && $http_header03=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header03=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri08 && $http_uri08=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri08=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_header13 && $http_header13=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header13=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
   while($http_uri18 && $http_uri18=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri18=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
   while($http_header23 && $http_header23=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header23=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
   while($http_uri28 && $http_uri28=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri28=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  # ne pas faire d'echappement sur la pcre ($pcre_uri33 et $pcre_agent34)
  my $abc1=0;
  my $httppcreagent=0;
  my $httpagentshort=0;
  my $httpagentshort_depth=0;
  my $httpagentshort_equal=0;
  my $httpreferer=0;
  my $httphost=0;
  my $pcrereferer=0;
  my $pcrehost=0;
  my $http_cookie=0;
  my $cookiepcre=0;
  my $http_host03=0;
  my $pcre_host34=0;
  my @tableauuri1;

     if( $http_header03 && $http_header03 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~ s/\QUser-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser-Agent\: \E$/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser-Agent\:\E$/i ) { undef($http_header03) }
  #$http_header03 =~ s/\Q\x0D\x0A\E/\$/i if $http_header03; # http_header, \x0D\x0A
     if( $http_header13 && $http_header13 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~ s/\QUser-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser-Agent\: \E$/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser-Agent\:\E$/i ) { undef($http_header13) }
  #$http_header13 =~ s/\Q\x0D\x0A\E/\$/i if $http_header13; # http_header, \x0D\x0A
     if( $http_header23 && $http_header23 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~ s/\QUser-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser-Agent\: \E$/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser-Agent\:\E$/i ) { undef($http_header23) }
  #$http_header23 =~ s/\Q\x0D\x0A\E/\$/i if $http_header23; # http_header, \x0D\x0A
  $pcre_agent34 =~ s/\Q^User\-Agent\x3A\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User-Agent\x3A\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User\-Agent\x3A \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser\-Agent\x3A\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser\-Agent\x3A \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User-Agent\x3A\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User-Agent\x3A \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser-Agent\x3A\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser-Agent\x3A \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User\-Agent\:\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User\-Agent\: \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser\-Agent\:\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser\-Agent\: \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User-Agent\:\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User-Agent\: \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser-Agent\:\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser-Agent\: \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User\-Agent\x3A\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser\-Agent\x3A\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User-Agent\x3A\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser-Agent\x3A\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User\-Agent\:\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser\-Agent\:\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User-Agent\:\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser-Agent\:\E/^/i if $pcre_agent34;
  #$pcre_agent34 =~ s/\Q\x0D\x0A\E/\$/i if $pcre_agent34; # http_header, \x0D\x0A
     if( $http_header03 && $http_header03 =~ s/\Q^Referer\x3A\x20\E/^/i ) { $http_header03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\Q^Referer\x3A \E/^/i ) { $http_header03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\QReferer\x3A\x20\E/^/i ) { $http_header03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\QReferer\x3A \E/^/i ) { $http_header03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header03; undef $http_header03 }
     if( $http_header13 && $http_header13 =~ s/\Q^Referer\x3A\x20\E/^/i ) { $http_header13=~s/\Q\x0D\x0A\E/\$/i;   $pcrereferer = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\Q^Referer\x3A \E/^/i ) { $http_header13=~s/\Q\x0D\x0A\E/\$/i;   $pcrereferer = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\QReferer\x3A\x20\E/^/i ) { $http_header13=~s/\Q\x0D\x0A\E/\$/i;   $pcrereferer = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\QReferer\x3A \E/^/i ) { $http_header13=~s/\Q\x0D\x0A\E/\$/i;   $pcrereferer = $http_header13; undef $http_header13 }
     if( $http_header23 && $http_header23 =~ s/\Q^Referer\x3A\x20\E/^/i ) { $http_header23 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\Q^Referer\x3A \E/^/i ) { $http_header23 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\QReferer\x3A\x20\E/^/i ) { $http_header23 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\QReferer\x3A \E/^/i ) { $http_header23 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header23; undef $http_header23 }

     if( $http_header03 && $http_header03 =~ s/\Q^Host\x3A\x20\E/^/i ) { $http_host03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrehost = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\Q^Host\x3A \E/^/i ) { $http_host03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrehost = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\QHost\x3A\x20\E/^/i ) { $http_host03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrehost = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\QHost\x3A \E/^/i ) { $http_host03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrehost = $http_header03; undef $http_header03 }
     if( $http_header13 && $http_header13 =~ s/\Q^Host\x3A\x20\E/^/i ) { $http_host03=~s/\Q\x0D\x0A\E/\$/i;   $pcrehost = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\Q^Host\x3A \E/^/i ) { $http_host03=~s/\Q\x0D\x0A\E/\$/i;   $pcrehost = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\QHost\x3A\x20\E/^/i ) { $http_host03=~s/\Q\x0D\x0A\E/\$/i;   $pcrehost = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\QHost\x3A \E/^/i ) { $http_host03=~s/\Q\x0D\x0A\E/\$/i;   $pcrehost = $http_header13; undef $http_header13 }
     if( $http_header23 && $http_header23 =~ s/\Q^Host\x3A\x20\E/^/i ) { $http_host03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrehost = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\Q^Host\x3A \E/^/i ) { $http_host03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrehost = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\QHost\x3A\x20\E/^/i ) { $http_host03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrehost = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\QHost\x3A \E/^/i ) { $http_host03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrehost = $http_header23; undef $http_header23 }

  $pcrereferer =~ s/(?<!\x5C)\x28/\x5C\x28/g if $pcrereferer; # (
  $pcrereferer =~ s/(?<!\x5C)\x29/\x5C\x29/g if $pcrereferer; # )
  $pcrereferer =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $pcrereferer; # *
  $pcrereferer =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $pcrereferer; # +
  $pcrereferer =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $pcrereferer; # -
  $pcrereferer =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $pcrereferer; # .
  $pcrereferer =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $pcrereferer; # /
  $pcrereferer =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $pcrereferer; # ?
  $pcrereferer =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $pcrereferer; # [
  $pcrereferer =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $pcrereferer; # ]
  #$pcrereferer =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $pcrereferer; # ^
  $pcrereferer =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $pcrereferer; # {
  $pcrereferer =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $pcrereferer; # }

  if( $pcrereferer !~ /\\x/ && $pcrereferer =~ /^\^/ && $pcrereferer !~ /^\^\\\-\$$/ )
  {
   $pcrereferer =~ s/\\//g;
   $pcrereferer =~ s/^\^//g;
   $pcrereferer =~ s/\$$//g;
   $httpreferer = $pcrereferer;
   $pcrereferer = 0;
  }

  if( $pcrehost !~ /\\x/ && $pcrehost =~ /^\^/ && $pcrehost !~ /^\^\\\-\$$/ )
  {
   $pcrehost =~ s/\\//g;
   $pcrehost =~ s/^\^//g;
   $pcrehost =~ s/\$$//g;
   $httphost = $pcrehost;
   $pcrehost = 0;
  }

     if( $pcre_agent34  && $pcre_agent34  =~ s/\Q^Referer\x3A\x20\E/^/i ) { $pcre_agent34 =~ s/\Q\x0D\x0A\E/\$/i;  $pcrereferer = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34  =~ s/\Q^Referer\x3A \E/^/i ) { $pcre_agent34 =~ s/\Q\x0D\x0A\E/\$/i;  $pcrereferer = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34  =~ s/\QReferer\x3A\x20\E/^/i ) { $pcre_agent34 =~ s/\Q\x0D\x0A\E/\$/i;  $pcrereferer = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34  =~ s/\QReferer\x3A \E/^/i ) { $pcre_agent34 =~ s/\Q\x0D\x0A\E/\$/i;  $pcrereferer = $pcre_agent34; undef $pcre_agent34 }

     if( $pcre_agent34  && $pcre_agent34  =~ s/\Q^Host\x3A\x20\E/^/i ) { $pcre_host34 =~ s/\Q\x0D\x0A\E/\$/i;  $pcrehost = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34  =~ s/\Q^Host\x3A \E/^/i ) { $pcre_host34 =~ s/\Q\x0D\x0A\E/\$/i;  $pcrehost = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34  =~ s/\QHost\x3A\x20\E/^/i ) { $pcre_host34 =~ s/\Q\x0D\x0A\E/\$/i;  $pcrehost = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34  =~ s/\QHost\x3A \E/^/i ) { $pcre_host34 =~ s/\Q\x0D\x0A\E/\$/i;  $pcrehost = $pcre_agent34; undef $pcre_agent34 }

     if( $http_header03 && $http_header03 =~ s/\Q\x0d\x0aCookie\x3A \E(?!$)/^/i ) { $http_cookie = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\QCookie\x3A \E(?!$)/^/i ) { $http_cookie = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\Q\x0d\x0aCookie\x3A\x20\E(?!$)/^/i ) { $http_cookie = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\QCookie\x3A\x20\E(?!$)/^/i ) { $http_cookie = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\Q\x0d\x0aCookie: \E(?!$)/^/i ) { $http_cookie = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\QCookie: \E(?!$)/^/i ) { $http_cookie = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\Q\x0d\x0aCookie:\x20\E(?!$)/^/i ) { $http_cookie = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\QCookie:\x20\E(?!$)/^/i ) { $http_cookie = $http_header03; undef $http_header03 }
     #if( $http_header03 && $http_header03 =~ s/\Q\x0D\x0A\E/\$/i ) { $http_cookie = $http_header03; undef $http_header03 }
     if( $http_header13 && $http_header13 =~ s/\Q\x0d\x0aCookie\x3A \E(?!$)/^/i ) { $http_cookie = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\QCookie\x3A \E(?!$)/^/i ) { $http_cookie = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\Q\x0d\x0aCookie\x3A\x20\E(?!$)/^/i ) { $http_cookie = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\QCookie\x3A\x20\E(?!$)/^/i ) { $http_cookie = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\Q\x0d\x0aCookie: \E(?!$)/^/i ) { $http_cookie = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\QCookie: \E(?!$)/^/i ) { $http_cookie = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\Q\x0d\x0aCookie:\x20\E(?!$)/^/i ) { $http_cookie = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\QCookie:\x20\E(?!$)/^/i ) { $http_cookie = $http_header13; undef $http_header13 }
     #if( $http_header13 && $http_header13 =~ s/\Q\x0D\x0A\E/\$/i ) { $http_cookie = $http_header13; undef $http_header13 }
     if( $http_header23 && $http_header23 =~ s/\Q\x0d\x0aCookie\x3A \E(?!$)/^/i ) { $http_cookie = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\QCookie\x3A \E(?!$)/^/i ) { $http_cookie = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\Q\x0d\x0aCookie\x3A\x20\E(?!$)/^/i ) { $http_cookie = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\QCookie\x3A\x20\E(?!$)/^/i ) { $http_cookie = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\Q\x0d\x0aCookie: \E(?!$)/^/i ) { $http_cookie = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\QCookie: \E(?!$)/^/i ) { $http_cookie = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\Q\x0d\x0aCookie:\x20\E(?!$)/^/i ) { $http_cookie = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\QCookie:\x20\E(?!$)/^/i ) { $http_cookie = $http_header23; undef $http_header23 }
     #if( $http_header23 && $http_header23 =~ s/\Q\x0D\x0A\E/\$/i ) { $http_cookie = $http_header23; undef $http_header23 }
     if( $pcre_agent34  && $pcre_agent34  =~ s/\Q\x0d\x0aCookie\x3A \E(?!$)/^/i ) { $http_cookie = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34  =~ s/\QCookie\x3A \E(?!$)/^/i ) { $http_cookie = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34 =~ s/\Q\x0d\x0aCookie\x3A\x20\E(?!$)/^/i ) { $http_cookie = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34 =~ s/\QCookie\x3A\x20\E(?!$)/^/i ) { $http_cookie = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34 =~ s/\Q\x0d\x0aCookie: \E(?!$)/^/i ) { $http_cookie = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34 =~ s/\QCookie: \E(?!$)/^/i ) { $http_cookie = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34 =~ s/\Q\x0d\x0aCookie:\x20\E(?!$)/^/i ) { $http_cookie = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34 =~ s/\QCookie:\x20\E(?!$)/^/i ) { $http_cookie = $pcre_agent34; undef $pcre_agent34 }
     #if( $pcre_agent34  && $pcre_agent34 =~ s/\Q\x0D\x0A\E/\$/i ) { $http_cookie = $pcre_agent34; undef $pcre_agent34 }

  $http_header03 =~ s/\Q\x0D\x0A\E/\$/i if $http_header03; # http_header, \x0D\x0A
  $http_header13 =~ s/\Q\x0D\x0A\E/\$/i if $http_header13; # http_header, \x0D\x0A
  $http_header23 =~ s/\Q\x0D\x0A\E/\$/i if $http_header23; # http_header, \x0D\x0A
  $pcre_agent34 =~ s/\Q\x0D\x0A\E/\$/i if $pcre_agent34; # http_header, \x0D\x0A
  $http_cookie =~ s/\Q\x0D\x0A\E/\$/i if $http_cookie; # http_header, \x0D\x0A

  if( $http_cookie and $http_cookie =~ /\\x/ )
  {
   $cookiepcre = $http_cookie if not $cookiepcre;
   $http_cookie=0;
  }
  elsif( $http_cookie and $http_cookie =~ /(?:\^|\$)/ )
  {
   $cookiepcre = $http_cookie if not $cookiepcre;
   $http_cookie =~ s/(?:\^|\$)//g;
  }
  elsif( $http_cookie and $http_cookie =~ /\\/ )
  {
   $http_cookie =~ s/\\//g;
  }

  if( $pcre_agent34 )
  {
   $pcre_agent34 =~ s/\Q^[^\r\n]+?\E//i;
   $pcre_agent34 =~ s/\Q^[^\r\n]+\E//i;
   $pcre_agent34 =~ s/\Q^[^\r\n]*?\E//i;
   $pcre_agent34 =~ s/\Q^[^\r\n]*\E//i;
   $pcre_agent34 =~ s/\Q^[^\n]+?\E//i;
   $pcre_agent34 =~ s/\Q^[^\n]+\E//i;
   $pcre_agent34 =~ s/\Q^[^\n]*?\E//i;
   $pcre_agent34 =~ s/\Q^[^\n]*\E//i;
  }

  #if( $pcre_uri33 )
  #{
  # $pcre_uri33 =~ s/^\^\\\//\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\\//i;
  # $pcre_uri33 =~ s/^\^\\x2F/\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\x2F/i;
  #}

  my $okremiseazeropcreagent34=0;
  if( $pcre_agent34 && $http_header03 && ( $pcre_agent34 =~ /^\^\[\^(?:\\r)?\\n(?:\\r)?\]\+(.*)$/ ) && ( $http_header03 eq $1 ) ) { $okremiseazeropcreagent34=1 }
  if( $pcre_agent34 && $http_header13 && ( $pcre_agent34 =~ /^\^\[\^(?:\\r)?\\n(?:\\r)?\]\+(.*)$/ ) && ( $http_header13 eq $1 ) ) { $okremiseazeropcreagent34=1 }
  if( $pcre_agent34 && $http_header23 && ( $pcre_agent34 =~ /^\^\[\^(?:\\r)?\\n(?:\\r)?\]\+(.*)$/ ) && ( $http_header23 eq $1 ) ) { $okremiseazeropcreagent34=1 }

  # http_user_agent short
  if( $http_header03 && $http_header13 && $http_header23 && length($http_header03) >= ( length($http_header13) or length($http_header23) ) )
  {
   $httpagentshort= "$http_header03" if $http_header03;
  }
  elsif( $http_header03 && $http_header13 && $http_header23 && length($http_header13) >= ( length($http_header03) or length($http_header23) ) )
  {
   $httpagentshort= "$http_header13" if $http_header13;
  }
  elsif( $http_header03 && $http_header13 && $http_header23 && length($http_header23) >= ( length($http_header03) or length($http_header13) ) )
  {
   $httpagentshort= "$http_header23" if $http_header23;
  }
  elsif( $http_header03 && $http_header13 && !$http_header23 && length($http_header03) >= length($http_header13) )
  {
   $httpagentshort= "$http_header03" if $http_header03;
  }
  elsif( $http_header03 && $http_header13 && !$http_header23 && length($http_header13) >= length($http_header03) )
  {
   $httpagentshort= "$http_header13" if $http_header13;
  }
  elsif( !$http_header03 && $http_header13 && $http_header23 && length($http_header13) >= length($http_header23) )
  {
   $httpagentshort= "$http_header13" if $http_header13;
  }
  elsif( !$http_header03 && $http_header13 && $http_header23 && length($http_header23) >= length($http_header13) )
  {
   $httpagentshort= "$http_header23" if $http_header23;
  }
  elsif( $http_header03 && !$http_header13 && $http_header23 && length($http_header03) >= length($http_header23) )
  {
   $httpagentshort= "$http_header03" if $http_header03;
  }
  elsif( $http_header03 && !$http_header13 && $http_header23 && length($http_header23) >= length($http_header03) )
  {
   $httpagentshort= "$http_header23" if $http_header23;
  }
  elsif( $http_header03 && !$http_header13 && !$http_header23 )
  {
   $httpagentshort= "$http_header03" if $http_header03;
  }
  elsif( !$http_header03 && $http_header13 && !$http_header23 )
  {
   $httpagentshort= "$http_header13" if $http_header13;
  }
  elsif( !$http_header03 && !$http_header13 && $http_header23 )
  {
   $httpagentshort= "$http_header23" if $http_header23;
  }
  while( $httpagentshort =~ /\\x(..)/g )
  {
   my $tempochr=chr(hex("$1"));
   $httpagentshort =~ s/\\x(..)/$tempochr/;
  }
  if( $httpagentshort =~ /^\^(?!\-\$)[^\$]*?\$/ )
  {
   $httpagentshort_equal=length($httpagentshort)-2;
  }
  elsif( $httpagentshort =~ /^\^(?!\-\$)/ )
  {
   $httpagentshort_depth=length($httpagentshort);
  }
  $httpagentshort =~ s/(?:\\(?!$)(?:x[a-f0-9]{2})?|\^|\$)//g;

  if( $pcre_agent34 && $http_header03 && $pcre_agent34=~/\Q$http_header03\E/i ) {
   undef $http_header03;
   print "ok trouvé grep3a\n" if $debug1;
  }
  elsif( $pcre_agent34 && $http_header03 && $http_header03=~s/\&/\\x26/g && $pcre_agent34=~/\Q$http_header03\E/i ) {
   undef $http_header03;
   print "ok trouvé grep3b\n" if $debug1;
  }
  elsif( $pcre_agent34 && $http_header03 && $http_header03=~s/\=/\\x3D/g && $pcre_agent34=~/\Q$http_header03\E/i ) {
   undef $http_header03;
   print "ok trouvé grep3c\n" if $debug1;
  }
  if( $pcre_uri33 && $http_uri08 && $pcre_uri33=~/\Q$http_uri08\E/i ) {
   undef $http_uri08;
   print "ok trouvé grep8a\n" if $debug1;
  }
  elsif( $pcre_uri33 && $http_uri08 && $http_uri08=~s/\&/\\x26/g && $pcre_uri33=~/\Q$http_uri08\E/i ) {
   undef $http_uri08;
   print "ok trouvé grep8b\n" if $debug1;
  }
  elsif( $pcre_uri33 && $http_uri08 && $http_uri08=~s/\=/\\x3D/g && $pcre_uri33=~/\Q$http_uri08\E/i ) {
   undef $http_uri08;
   print "ok trouvé grep8c\n" if $debug1;
  }
  if( $pcre_agent34 && $http_header13 && $pcre_agent34=~/\Q$http_header13\E/i ) {
   undef $http_header13;
   print "ok trouvé grep13a\n" if $debug1;
  }
  elsif( $pcre_agent34 && $http_header13 && $http_header13=~s/\&/\\x26/g && $pcre_agent34=~/\Q$http_header13\E/i ) {
   undef $http_header13;
   print "ok trouvé grep13b\n" if $debug1;
  }
  elsif( $pcre_agent34 && $http_header13 && $http_header13=~s/\=/\\x3D/g && $pcre_agent34=~/\Q$http_header13\E/i ) {
   undef $http_header13;
   print "ok trouvé grep13c\n" if $debug1;
  }
  if( $pcre_uri33 && $http_uri18 && $pcre_uri33=~/\Q$http_uri18\E/i ) {
   undef $http_uri18;
   print "ok trouvé grep18\n" if $debug1;
  }
  elsif( $pcre_uri33 && $http_uri18 && $http_uri18=~s/\&/\\x26/g && $pcre_uri33=~/\Q$http_uri18\E/i ) {
   undef $http_uri18;
   print "ok trouvé grep18\n" if $debug1;
  }
  elsif( $pcre_uri33 && $http_uri18 && $http_uri18=~s/\=/\\x3D/g && $pcre_uri33=~/\Q$http_uri18\E/i ) {
   undef $http_uri18;
   print "ok trouvé grep18\n" if $debug1;
  }
  if( $pcre_agent34 && $http_header23 && $pcre_agent34=~/\Q$http_header23\E/i ) {
   undef $http_header23;
   print "ok trouvé grep23\n" if $debug1;
  }
  elsif( $pcre_agent34 && $http_header23 && $http_header23=~s/\&/\\x26/g && $pcre_agent34=~/\Q$http_header23\E/i ) {
   undef $http_header23;
   print "ok trouvé grep23\n" if $debug1;
  }
  elsif( $pcre_agent34 && $http_header23 && $http_header23=~s/\=/\\x3D/g && $pcre_agent34=~/\Q$http_header23\E/i ) {
   undef $http_header23;
   print "ok trouvé grep23\n" if $debug1;
  }
  if( $pcre_uri33 && $http_uri28 && $pcre_uri33=~/\Q$http_uri28\E/i ) {
   undef $http_uri28;
   print "ok trouvé grep28\n" if $debug1;
  }
  elsif( $pcre_uri33 && $http_uri28 && $http_uri28=~s/\&/\\x26/g && $pcre_uri33=~/\Q$http_uri28\E/i ) {
   undef $http_uri28;
   print "ok trouvé grep28\n" if $debug1;
  }
  elsif( $pcre_uri33 && $http_uri28 && $http_uri28=~s/\=/\\x3D/g && $pcre_uri33=~/\Q$http_uri28\E/i ) {
   undef $http_uri28;
   print "ok trouvé grep28\n" if $debug1;
  }

  # one header
  if( $http_header03 && !$http_header13 && !$http_header23 && !$pcre_agent34 )
  {
   $http_header03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header03; # (
   $http_header03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header03; # )
   $http_header03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header03; # *
   $http_header03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header03; # +
   $http_header03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header03; # -
   $http_header03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header03; # .
   $http_header03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header03; # /
   $http_header03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header03; # ?
   $http_header03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header03; # [
   $http_header03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header03; # ]
   #$http_header03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header03; # ^
   $http_header03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header03; # {
   $http_header03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header03; # }
   $httppcreagent= "$http_header03";
  }
  if( $http_header13 && !$http_header03 && !$http_header23 && !$pcre_agent34 )
  {
   $http_header13 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header13; # (
   $http_header13 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header13; # )
   $http_header13 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header13; # *
   $http_header13 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header13; # +
   $http_header13 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header13; # -
   $http_header13 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header13; # .
   $http_header13 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header13; # /
   $http_header13 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header13; # ?
   $http_header13 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header13; # [
   $http_header13 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header13; # ]
   #$http_header13 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header13; # ^
   $http_header13 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header13; # {
   $http_header13 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header13; # }
   $httppcreagent= "$http_header13";
  }
  if( $http_header23 && !$http_header03 && !$http_header13 && !$pcre_agent34 )
  {
   $http_header23 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header23; # (
   $http_header23 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header23; # )
   $http_header23 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header23; # *
   $http_header23 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header23; # +
   $http_header23 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header23; # -
   $http_header23 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header23; # .
   $http_header23 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header23; # /
   $http_header23 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header23; # ?
   $http_header23 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header23; # [
   $http_header23 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header23; # ]
   #$http_header23 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header23; # ^
   $http_header23 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header23; # {
   $http_header23 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header23; # }
   $httppcreagent= "$http_header23";
  }
  $httppcreagent= "$pcre_agent34" if $pcre_agent34 && !$http_header03 && !$http_header13 && !$http_header23;
  unless( $httppcreagent && ($httppcreagent =~/(?:\\|\^|\$)/) ) { $httppcreagent=0 }

  # one uri
  #$abc1= "$http_uri08" if $http_uri08 && !$http_uri18 && !$http_uri28;
  #$abc1= "$http_uri18" if $http_uri18 && !$http_uri08 && !$http_uri28;
  #$abc1= "$http_uri28" if $http_uri28 && !$http_uri08 && !$http_uri18;
  $abc1= "$pcre_uri33" if $pcre_uri33 && !$http_uri08 && !$http_uri18;

  # two headers
  if( (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
   # escape:
   $http_header03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header03; # (
   $http_header03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header03; # )
   $http_header03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header03; # *
   $http_header03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header03; # +
   $http_header03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header03; # -
   $http_header03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header03; # .
   $http_header03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header03; # /
   $http_header03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header03; # ?
   $http_header03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header03; # [
   $http_header03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header03; # ]
   #$http_header03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header03; # ^
   $http_header03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header03; # {
   $http_header03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header03; # }
   $http_header13 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header13; # (
   $http_header13 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header13; # )
   $http_header13 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header13; # *
   $http_header13 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header13; # +
   $http_header13 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header13; # -
   $http_header13 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header13; # .
   $http_header13 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header13; # /
   $http_header13 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header13; # ?
   $http_header13 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header13; # [
   $http_header13 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header13; # ]
   #$http_header13 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header13; # ^
   $http_header13 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header13; # {
   $http_header13 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header13; # }
   $httppcreagent= "(?:$http_header03.*?$http_header13)" if $http_header03 && $http_header13 && !$http_header23 && !$pcre_agent34;
  }
  elsif( !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
   # escape:
   $http_header03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header03; # (
   $http_header03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header03; # )
   $http_header03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header03; # *
   $http_header03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header03; # +
   $http_header03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header03; # -
   $http_header03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header03; # .
   $http_header03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header03; # /
   $http_header03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header03; # ?
   $http_header03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header03; # [
   $http_header03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header03; # ]
   #$http_header03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header03; # ^
   $http_header03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header03; # {
   $http_header03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header03; # }
   $http_header13 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header13; # (
   $http_header13 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header13; # )
   $http_header13 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header13; # *
   $http_header13 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header13; # +
   $http_header13 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header13; # -
   $http_header13 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header13; # .
   $http_header13 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header13; # /
   $http_header13 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header13; # ?
   $http_header13 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header13; # [
   $http_header13 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header13; # ]
   #$http_header13 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header13; # ^
   $http_header13 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header13; # {
   $http_header13 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header13; # }
   $http_header23 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header23; # (
   $http_header23 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header23; # )
   $http_header23 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header23; # *
   $http_header23 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header23; # +
   $http_header23 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header23; # -
   $http_header23 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header23; # .
   $http_header23 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header23; # /
   $http_header23 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header23; # ?
   $http_header23 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header23; # [
   $http_header23 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header23; # ]
   #$http_header23 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header23; # ^
   $http_header23 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header23; # {
   $http_header23 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header23; # }
   $httppcreagent= "(?:$http_header03.*?$http_header13|$http_header13.*?$http_header03)" if $http_header03 && $http_header13 && !$http_header23 && !$pcre_agent34;
   $httppcreagent= "(?:$http_header03.*?$http_header23|$http_header23.*?$http_header03)" if $http_header03 && $http_header23 && !$http_header13 && !$pcre_agent34;
   $httppcreagent= "(?:$http_header03.*?$pcre_agent34|$pcre_agent34.*?$http_header03)" if $http_header03 && $pcre_agent34 && !$http_header13 && !$http_header23;
  }

  # two uri
  if( (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && !(defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) ) {
   $abc1= "(?:$http_uri08.*?$http_uri18)" if $http_uri08 && $http_uri18 && !$http_uri28 && !$pcre_uri33;
  }
  elsif( !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && !(defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) ) {
   if( $http_uri08 && $http_uri18 && !$http_uri28 && !$pcre_uri33 && (( $http_uri08 !~ /\\x|^\^|\$$/ ) or ( $http_uri18 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri08, $http_uri18 ) if $http_uri08 && $http_uri18 && !$pcre_uri33;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
   else
   {
    $abc1= "(?:$http_uri08.*?$http_uri18|$http_uri18.*?$http_uri08)" if $http_uri08 && $http_uri18 && !$http_uri28 && !$pcre_uri33;
   }

   $abc1= "(?:$http_uri08.*?$pcre_uri33|$pcre_uri33.*?$http_uri08)" if $http_uri08 && $pcre_uri33 && !$http_uri18 && !$http_uri28;
  }

  # three headers
  if( (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
   # escape:
   $http_header03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header03; # (
   $http_header03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header03; # )
   $http_header03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header03; # *
   $http_header03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header03; # +
   $http_header03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header03; # -
   $http_header03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header03; # .
   $http_header03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header03; # /
   $http_header03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header03; # ?
   $http_header03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header03; # [
   $http_header03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header03; # ]
   #$http_header03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header03; # ^
   $http_header03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header03; # {
   $http_header03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header03; # }
   $http_header13 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header13; # (
   $http_header13 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header13; # )
   $http_header13 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header13; # *
   $http_header13 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header13; # +
   $http_header13 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header13; # -
   $http_header13 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header13; # .
   $http_header13 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header13; # /
   $http_header13 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header13; # ?
   $http_header13 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header13; # [
   $http_header13 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header13; # ]
   #$http_header13 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header13; # ^
   $http_header13 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header13; # {
   $http_header13 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header13; # }
   $http_header23 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header23; # (
   $http_header23 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header23; # )
   $http_header23 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header23; # *
   $http_header23 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header23; # +
   $http_header23 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header23; # -
   $http_header23 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header23; # .
   $http_header23 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header23; # /
   $http_header23 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header23; # ?
   $http_header23 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header23; # [
   $http_header23 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header23; # ]
   #$http_header23 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header23; # ^
   $http_header23 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header23; # {
   $http_header23 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header23; # }
   $httppcreagent= "(?:$http_header03.*$http_header13.*$http_header23)" if $http_header03 && $http_header13 && $http_header23 && !$pcre_agent34;
  }
  elsif( !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
   # escape:
   $http_header03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header03; # (
   $http_header03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header03; # )
   $http_header03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header03; # *
   $http_header03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header03; # +
   $http_header03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header03; # -
   $http_header03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header03; # .
   $http_header03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header03; # /
   $http_header03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header03; # ?
   $http_header03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header03; # [
   $http_header03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header03; # ]
   #$http_header03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header03; # ^
   $http_header03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header03; # {
   $http_header03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header03; # }
   $http_header13 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header13; # (
   $http_header13 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header13; # )
   $http_header13 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header13; # *
   $http_header13 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header13; # +
   $http_header13 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header13; # -
   $http_header13 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header13; # .
   $http_header13 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header13; # /
   $http_header13 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header13; # ?
   $http_header13 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header13; # [
   $http_header13 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header13; # ]
   #$http_header13 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header13; # ^
   $http_header13 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header13; # {
   $http_header13 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header13; # }
   $http_header23 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header23; # (
   $http_header23 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header23; # )
   $http_header23 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header23; # *
   $http_header23 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header23; # +
   $http_header23 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header23; # -
   $http_header23 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header23; # .
   $http_header23 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header23; # /
   $http_header23 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header23; # ?
   $http_header23 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header23; # [
   $http_header23 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header23; # ]
   #$http_header23 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header23; # ^
   $http_header23 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header23; # {
   $http_header23 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header23; # }
   $httppcreagent= "(?:$http_header03.*$http_header13.*$http_header23|$http_header03.*$http_header23.*$http_header13|$http_header23.*$http_header03.*$http_header13|$http_header23.*$http_header13.*$http_header03)" if $http_header03 && $http_header13 && $http_header23 && !$pcre_agent34;
   $httppcreagent= "(?:$http_header03.*$http_header13.*$pcre_agent34|$http_header03.*$pcre_agent34.*$http_header13|$pcre_agent34.*$http_header03.*$http_header13|$pcre_agent34.*$http_header13.*$http_header03)" if $http_header03 && $http_header13 && $pcre_agent34 && !$http_header23;
  }

  # three uri
  if( (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && (defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) ) {
   $abc1= "(?:$http_uri08.*$http_uri18.*$pcre_uri33)" if $http_uri08 && $http_uri18 && $pcre_uri33 && !$http_uri28;
  }
  elsif( !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && !(defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) ) {
   if( $http_uri08 && $http_uri18 && $http_uri28 && !$pcre_uri33 && (( $http_uri08 !~ /\\x|^\^|\$$/ ) or ( $http_uri18 !~ /\\x|^\^|\$$/ ) or ( $http_uri28 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri08, $http_uri18, $http_uri28 ) if $http_uri08 && $http_uri18 && $http_uri28 && !$pcre_uri33;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
   else
   {
   $abc1= "(?:$http_uri08.*$http_uri18.*$http_uri28|$http_uri08.*$http_uri28.*$http_uri18|$http_uri28.*$http_uri08.*$http_uri18|$http_uri28.*$http_uri18.*$http_uri08)" if $http_uri08 && $http_uri18 && $http_uri28 && !$pcre_uri33;
   }
   $abc1= "(?:$http_uri08.*$http_uri18.*$pcre_uri33|$http_uri08.*$pcre_uri33.*$http_uri18|$pcre_uri33.*$http_uri08.*$http_uri18|$pcre_uri33.*$http_uri18.*$http_uri08)" if $http_uri08 && $http_uri18 && $pcre_uri33 && !$http_uri28;
  }

  # four headers
   if( $http_header03 && $http_header13 && $http_header23 && $pcre_agent34 )
   {
    # escape:
    $http_header03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header03; # (
    $http_header03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header03; # )
    $http_header03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header03; # *
    $http_header03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header03; # +
    $http_header03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header03; # -
    $http_header03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header03; # .
    $http_header03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header03; # /
    $http_header03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header03; # ?
    $http_header03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header03; # [
    $http_header03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header03; # ]
    #$http_header03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header03; # ^
    $http_header03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header03; # {
    $http_header03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header03; # }
    $http_header13 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header13; # (
    $http_header13 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header13; # )
    $http_header13 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header13; # *
    $http_header13 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header13; # +
    $http_header13 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header13; # -
    $http_header13 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header13; # .
    $http_header13 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header13; # /
    $http_header13 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header13; # ?
    $http_header13 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header13; # [
    $http_header13 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header13; # ]
    #$http_header13 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header13; # ^
    $http_header13 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header13; # {
    $http_header13 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header13; # }
    $http_header23 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header23; # (
    $http_header23 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header23; # )
    $http_header23 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header23; # *
    $http_header23 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header23; # +
    $http_header23 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header23; # -
    $http_header23 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header23; # .
    $http_header23 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header23; # /
    $http_header23 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header23; # ?
    $http_header23 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header23; # [
    $http_header23 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header23; # ]
    #$http_header23 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header23; # ^
    $http_header23 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header23; # {
    $http_header23 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header23; # }
    $httppcreagent= "(?:$http_header03.*$http_header13.*$http_header23.*$pcre_agent34|$http_header03.*$http_header13.*$pcre_agent34.*$http_header23|$http_header03.*$http_header23.*$http_header13.*$pcre_agent34|$http_header03.*$http_header23.*$pcre_agent34.*$http_header13|$http_header13.*$http_header23.*$pcre_agent34.*$http_header03|$http_header13.*$http_header23.*$http_header03.*$pcre_agent34|$http_header13.*$http_header03.*$http_header23.*$pcre_agent34|$http_header13.*$http_header03.*$pcre_agent34.*$http_header23|$http_header23.*$http_header03.*$http_header13.*$pcre_agent34|$http_header23.*$http_header03.*$pcre_agent34.*$http_header13|$http_header23.*$http_header13.*$pcre_agent34.*$http_header03|$http_header23.*$http_header13.*$http_header03.*$pcre_agent34|$pcre_agent34.*$http_header03.*$http_header13.*$http_header23|$pcre_agent34.*$http_header03.*$http_header23.*$http_header13|$pcre_agent34.*$http_header23.*$http_header03.*$http_header13|$pcre_agent34.*$http_header23.*$http_header13.*$http_header03)";
   }

  # four uri
   $abc1= "(?:$http_uri08.*$http_uri18.*$http_uri28.*$pcre_uri33|$http_uri08.*$http_uri18.*$pcre_uri33.*$http_uri28|$http_uri08.*$http_uri28.*$http_uri18.*$pcre_uri33|$http_uri08.*$http_uri28.*$pcre_uri33.*$http_uri18|$http_uri18.*$http_uri28.*$pcre_uri33.*$http_uri08|$http_uri18.*$http_uri28.*$http_uri08.*$pcre_uri33|$http_uri18.*$http_uri08.*$http_uri28.*$pcre_uri33|$http_uri18.*$http_uri08.*$pcre_uri33.*$http_uri28|$http_uri28.*$http_uri08.*$http_uri18.*$pcre_uri33|$http_uri28.*$http_uri08.*$pcre_uri33.*$http_uri18|$http_uri28.*$http_uri18.*$pcre_uri33.*$http_uri08|$http_uri28.*$http_uri18.*$http_uri08.*$pcre_uri33|$pcre_uri33.*$http_uri08.*$http_uri18.*$http_uri28|$pcre_uri33.*$http_uri08.*$http_uri28.*$http_uri18|$pcre_uri33.*$http_uri28.*$http_uri08.*$http_uri18|$pcre_uri33.*$http_uri28.*$http_uri18.*$http_uri08)" if $http_uri08 && $http_uri18 && $http_uri28 && $pcre_uri33;

  if( $okremiseazeropcreagent34 ) { undef $httppcreagent }

  # uri:
  my $abc1_nocase=0;
     $abc1_nocase=$http_urifast14   if $http_urifast14;
     $abc1_nocase=$http_urinocase12 if $http_urinocase12;
     $abc1_nocase=$http_urifast18   if $http_urifast18;
     $abc1_nocase=$http_urinocase15 if $http_urinocase15;
     $abc1_nocase=$http_urifast32   if $http_urifast32;
     $abc1_nocase=$http_urinocase25 if $http_urinocase25;
     $abc1_nocase=$http_urifast36   if $http_urifast36;
     $abc1_nocase=$http_urinocase28 if $http_urinocase28;
     $abc1_nocase=$http_urifast50   if $http_urifast50;
     $abc1_nocase=$http_urinocase39 if $http_urinocase39;
     $abc1_nocase=$http_urifast54   if $http_urifast54;
     $abc1_nocase=$http_urinocase42 if $http_urinocase42;
  # header:
  my $httppcreagent_nocase=0;
     $httppcreagent_nocase=$http_headerfast5    if $http_headerfast5;
     $httppcreagent_nocase=$http_headernocase5  if $http_headernocase5;
     $httppcreagent_nocase=$http_headerfast9    if $http_headerfast9;
     $httppcreagent_nocase=$http_headernocase8  if $http_headernocase8;
     $httppcreagent_nocase=$http_headerfast23   if $http_headerfast23;
     $httppcreagent_nocase=$http_headernocase19 if $http_headernocase19;
     $httppcreagent_nocase=$http_headerfast27   if $http_headerfast27;
     $httppcreagent_nocase=$http_headernocase22 if $http_headernocase22;
     $httppcreagent_nocase=$http_headerfast41   if $http_headerfast41;
     $httppcreagent_nocase=$http_headernocase32 if $http_headernocase32;
     $httppcreagent_nocase=$http_headerfast45   if $http_headerfast45;
     $httppcreagent_nocase=$http_headernocase35 if $http_headernocase35;

  if( $httpagentshort && $httppcreagent )
  {
   my $tempopcreagent = $httppcreagent;
   my $tempopcreagent2;
   while( $tempopcreagent && $tempopcreagent =~ /\\(?!$)x([a-f0-9]{2})?/g ) {
    my $toto1=chr(hex($1)) if $1;
    print "uaici4a: $toto1\n" if $debug1 && $toto1;
    $tempopcreagent =~ s/\\(?!$)x([a-f0-9]{2})?/$toto1/ if $toto1;
   }
   $tempopcreagent =~ s/\\(?!$)(?:x[a-f0-9]{2})?//g;
   print "uaici4b: $httpagentshort\n" if $debug1;
   print "uaici4c: $httppcreagent\n" if $debug1;
   print "uaici4d: $tempopcreagent\n" if $debug1;
   if( $httpagentshort eq $tempopcreagent )
   {
    print "tempopcreagent4: $tempopcreagent\n" if $debug1;
    undef $httppcreagent;
    undef $tempopcreagent;
   }
   elsif( $tempopcreagent =~ /^\^(?!\-\$)([^\$]*?)\$/ && $httpagentshort eq $1 )
   {
    print "uaici4e: $1\n" if $debug1;
    $httpagentshort_equal=length($tempopcreagent)-2;
    undef $httppcreagent;
    undef $tempopcreagent;
    undef $tempopcreagent2;
    print "uaici4f: $httpagentshort_equal\n" if $debug1;
   }
   elsif( $tempopcreagent =~ /^\^(.*)/ && $httpagentshort eq $1 )
   {
    print "uaici4g: $1\n" if $debug1;
    $httpagentshort_depth = length($tempopcreagent)-1;
    undef $httppcreagent;
    undef $tempopcreagent;
    undef $tempopcreagent2;
    print "uaici4h: $httpagentshort_depth\n" if $debug1;
   }
  }

 if( !@year2 || grep(/$metadatacreatedyear/, @year2) )
 {
  print "httpuricourt4: $etmsg1, ".lc($httpuricourt) if $debug1 && $httpuricourt; print ", depth: $http_uridepth" if $debug1 && $httpuricourt && $http_uridepth; print ", offset: $http_urioffset" if $debug1 && $httpuricourt && $http_urioffset; print "\n" if $debug1 && $httpuricourt;
  print "httpurilong4: $etmsg1, @tableauuri1\n" if $debug1 && @tableauuri1;
  print "tableaupcreuri4: $etmsg1, $abc1, $abc1_nocase\n" if $debug1 && $abc1;
  print "tableaupcreagent4: $etmsg1, $httppcreagent, $httppcreagent_nocase\n" if $debug1 && $httppcreagent;
  print "httpagentshort4: $etmsg1, ".lc($httpagentshort) if $debug1 && $httpagentshort; print ", depth=$httpagentshort_depth" if $debug1 && $httpagentshort_depth; print ", equal=$httpagentshort_equal" if $debug1 && $httpagentshort_equal; print "\n" if $debug1 && $httpagentshort;
  print "tableauhttpmethod4: $etmsg1, $http_method4, $http_methodnocase4\n" if $debug1 && $http_method4;
  print "httpreferer4: $etmsg1, ".lc($httpreferer)."\n" if $debug1 && $httpreferer;
  print "tableaupcrereferer4: $etmsg1, $pcrereferer\n" if $debug1 && $pcrereferer;
  print "tableauhttpcookie4: $etmsg1, $http_cookie\n" if $debug1 && $http_cookie;
  print "tableaupcrecookie4: $etmsg1, $cookiepcre\n" if $debug1 && $cookiepcre;
  print "httphost4: $etmsg1, ".lc($httphost)."\n" if $debug1 && $httphost;
  print "tableaupcrehost4: $etmsg1, $pcrehost\n" if $debug1 && $pcrehost;
  print "http_urilen4: $etmsg1, $http_urilen4\n" if $debug1 && $http_urilen4;
  print "metadata_created_year4: $etmsg1, $metadatacreatedyear\n" if $debug1 && $metadatacreatedyear;

  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt), $http_uridepth, $http_urioffset ] if $httpuricourt && $http_uridepth && $http_urioffset;
  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt), $http_uridepth ] if $httpuricourt && $http_uridepth && !$http_urioffset;
  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt) ] if $httpuricourt && !$http_uridepth && !$http_urioffset;
  $hash{$etmsg1}{httpagentshort} = [ lc($httpagentshort), "" , $httpagentshort_equal ] if $httpagentshort && !$httpagentshort_depth && $httpagentshort_equal;
  $hash{$etmsg1}{httpagentshort} = [ lc($httpagentshort), $httpagentshort_depth ] if $httpagentshort && $httpagentshort_depth && !$httpagentshort_equal;
  $hash{$etmsg1}{httpagentshort} = [ lc($httpagentshort) ] if $httpagentshort && !$httpagentshort_depth && !$httpagentshort_equal;
  $hash{$etmsg1}{httpmethod} = [ $http_method4, $http_methodnocase4 ] if $http_method4;
  $hash{$etmsg1}{httpreferer} = [ lc($httpreferer) ] if $httpreferer;
  $hash{$etmsg1}{pcrereferer} = [ $pcrereferer ] if $pcrereferer;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{pcreagent} = [ $httppcreagent, $httppcreagent_nocase ] if $httppcreagent;
  $hash{$etmsg1}{httpcookie} = [ $http_cookie ] if $http_cookie;
  $hash{$etmsg1}{pcrecookie} = [ $cookiepcre ] if $cookiepcre;
  $hash{$etmsg1}{httpurilong} = [ @tableauuri1 ] if @tableauuri1;
  $hash{$etmsg1}{httphost} = [ lc($httphost) ] if $httphost;
  $hash{$etmsg1}{pcrehost} = [ $pcrehost ] if $pcrehost;
  $hash{$etmsg1}{httpurilen} = [ $http_urilen4 ] if $http_urilen4;
 }

  next;
 }


 # begin http_uri followed by http_cookie
# elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$httpmethod)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)?\s*http_uri\;(?:$contentoptions1)?(?:$negateuricontent1)?)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)?\s*http_cookie\;(?:$contentoptions1)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:$pcreuri)?(?:$pcrecookie)?(?:$extracontentoptions)?$referencesidrev$/ )
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$httpmethod)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)?\s*http_uri\;(?:$contentoptions1)?(?:$negateuricontent1)?)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)?\s*http_cookie\;(?:$contentoptions1)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:$pcreuri)?(?:$pcrecookie)?(?:$extracontentoptions)?$referencesidrev[^\n]*$createdat/ )
 {
  my $http_method5=0;
  my $http_methodnocase5=0;
  #
  if( $debug1 ){
   print "brut5: $_\n"; print "here5: 1: $1," if $1; print " 2: $2," if $2; print " 3: $3," if $3; print " 4: $4," if $4; print " 5: $5," if $5; print " 6: $6," if $6; print " 7: $7," if $7; print " 8: $8," if $8; print " 9: $9," if $9; print " 10: $10," if $10; print " 11: $11," if $11; print " 12: $12," if $12; print " 13: $13," if $13; print " 14: $14," if $14; print " 15: $15," if $15; print " 16: $16," if $16; print " 17: $17," if $17; print " 18: $18," if $18; print " 19: $19," if $19; print " 20: $20," if $20; print " 21: $21," if $21; print " 22: $22," if $22; print " 23: $23," if $23; print " 24: $24," if $24; print " 25: $25," if $25; print " 26: $26," if $26; print " 27: $27," if $27; print " 28: $28," if $28; print " 29: $29," if $29; print " 30: $30," if $30; print " 31: $31," if $31; print " 32: $32" if $32; print "\n";
  }
  #
  my $etmsg1=$1;
  #
     $http_method5=$2 if $2;
     $http_methodnocase5=$3 if $3;
  #
  my $http_uri03=$4 if $4;		# old 4
  # fastpattern
  my $http_urinocase5=$6 if $6;
  # offset/depth
  # offset/depth
  # distance
  # distance
  # fastpattern
  my $http_urinocase8=$12 if $12;
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $http_cookie=$17 if $17;		# old 13
  # fastpattern
  my $http_cookienocase12=$19 if $19;
  # offset/depth
  # offset/depth
  # distance
  # distance
  # fastpattern
  my $http_cookienocase15=$25 if $25;
  # offset/depth
  # offset/depth
  # distance
  # distance
  #
  my $pcre_uri13=$30 if $30;		# old 22
  #
  my $cookiepcre=$31 if $31;		# old 23
  my $metadatacreatedyear=$32 if $32;

  # check what is http_uri best length ?
  my $httpuricourt=0;
     $httpuricourt=$http_uri03 if $http_uri03;

  # need escape special char before compare with pcre
  $http_uri03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri03 && $pcre_uri13; # (
  $http_uri03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri03 && $pcre_uri13; # )
  $http_uri03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri03 && $pcre_uri13; # *
  $http_uri03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri03 && $pcre_uri13; # +
  $http_uri03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri03 && $pcre_uri13; # -
  $http_uri03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri03 && $pcre_uri13; # .
  $http_uri03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri03 && $pcre_uri13; # /
  $http_uri03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri03 && $pcre_uri13; # ?
  $http_uri03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri03 && $pcre_uri13; # [
  $http_uri03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri03 && $pcre_uri13; # ]
  $http_uri03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri03 && $pcre_uri13; # ^
  $http_uri03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri03 && $pcre_uri13; # {
  $http_uri03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri03 && $pcre_uri13; # }
  $http_cookie =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_cookie && $cookiepcre; # (
  $http_cookie =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_cookie && $cookiepcre; # )
  $http_cookie =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_cookie && $cookiepcre; # *
  $http_cookie =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_cookie && $cookiepcre; # +
  $http_cookie =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_cookie && $cookiepcre; # -
  $http_cookie =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_cookie && $cookiepcre; # .
  $http_cookie =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_cookie && $cookiepcre; # /
  $http_cookie =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_cookie && $cookiepcre; # ?
  $http_cookie =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_cookie && $cookiepcre; # [
  $http_cookie =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_cookie && $cookiepcre; # ]
  $http_cookie =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_cookie && $cookiepcre; # ^
  $http_cookie =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_cookie && $cookiepcre; # {
  $http_cookie =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_cookie && $cookiepcre; # }
  #$pcre_uri13 =~ s/(?<!\x5C)\x24//g         if $pcre_uri13; # $
#perl -e '$abc1="1|20 21|2|22 24|3";while($abc1=~/(?<!\x5C)\|(.*?)\|/g){$toto1=$1;print "abc1:$abc1\ntoto1:$toto1\n";$toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g; print "$toto1\n"; $abc1=~s/(?<!\x5C)\|.*?\|/$toto1/}; print "final:$abc1\n"'
  while($http_uri03 && $http_uri03=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri03=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_cookie && $http_cookie=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_cookie=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  # ne pas faire d'echappement sur la pcre ($pcre_uri13)
  my $abc1;
  my $cookie=0;

     if( $http_cookie && $http_cookie =~ s/\QCookie\x3A \E(?!$)/^/i ) { }
  elsif( $http_cookie && $http_cookie =~ s/\QCookie\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_cookie && $http_cookie =~ s/\QCookie: \E(?!$)/^/i ) { }
  elsif( $http_cookie && $http_cookie =~ s/\QCookie:\x20\E(?!$)/^/i ) { }
  $http_cookie =~ s/\Q\x0D\x0A\E/\$/i if $http_cookie;

  if( $http_cookie and $http_cookie =~ /\\x/ )
  {
   $cookiepcre = $http_cookie if not $cookiepcre;
   $http_cookie=0;
  }
  elsif( $http_cookie and $http_cookie =~ /(?:\^|\$)/ )
  {
   $cookiepcre = $http_cookie if not $cookiepcre;
   $http_cookie =~ s/(?:\^|\$)//g;
  }
  elsif( $http_cookie and $http_cookie =~ /\\/ )
  {
   $http_cookie =~ s/\\//g;
  }

  #if( $pcre_uri13 )
  #{
  # $pcre_uri13 =~ s/^\^\\\//\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\\//i;
  # $pcre_uri13 =~ s/^\^\\x2F/\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\x2F/i;
  #}

  if( $pcre_uri13 && $http_uri03 && $pcre_uri13=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouvé grep3\n" if $debug1;
  }
  elsif( $pcre_uri13 && $http_uri03 && $http_uri03=~s/\&/\\x26/g && $pcre_uri13=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouvé grep3\n" if $debug1;
  }
  elsif( $pcre_uri13 && $http_uri03 && $http_uri03=~s/\=/\\x3D/g && $pcre_uri13=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouvé grep3\n" if $debug1;
  }

  $abc1= "$http_uri03" if $http_uri03 && !$pcre_uri13;
  $abc1= "$pcre_uri13" if $pcre_uri13 && !$http_uri03;
  $abc1= "(?:$http_uri03.*?$pcre_uri13|$pcre_uri13.*?$http_uri03)" if $http_uri03 && $pcre_uri13;

  my $abc1_nocase=0;

  if( $httpuricourt && $abc1 )
  {
   my $tempopcreuri = $abc1;
   $tempopcreuri =~ s/\\//g;
   if( $httpuricourt eq $tempopcreuri )
   {
    print "tempopcreuri: $tempopcreuri\n" if $debug1;
    undef $abc1;
    undef $tempopcreuri;
   }
  }

  # cookie:
  my $http_cookie_nocase=0;
     $http_cookie_nocase=$http_cookienocase12 if $http_cookienocase12;
     $http_cookie_nocase=$http_cookienocase15 if $http_cookienocase15;

 if( !@year2 || grep(/$metadatacreatedyear/, @year2) )
 {
  print "httpuricourt5: $etmsg1, ".lc($httpuricourt)."\n" if $debug1 && $httpuricourt;
  print "tableaupcreuri5: $etmsg1, $abc1, $abc1_nocase\n" if $debug1 && $abc1;
  print "tableauhttpmethod5: $etmsg1, $http_method5, $http_methodnocase5\n" if $debug1 && $http_method5;
  print "tableauhttpcookie5: $etmsg1, $http_cookie, $http_cookie_nocase\n" if $debug1 && $http_cookie;
  print "tableaupcrecookie5: $etmsg1, $cookiepcre, $http_cookie_nocase\n" if $debug1 && $cookiepcre;
  print "metadata_created_year5: $etmsg1, $metadatacreatedyear\n" if $debug1 && $metadatacreatedyear;

  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt) ] if $httpuricourt;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{httpmethod} = [ $http_method5, $http_methodnocase5 ] if $http_method5;
  $hash{$etmsg1}{httpcookie} = [ $http_cookie, $http_cookie_nocase ] if $http_cookie;
  $hash{$etmsg1}{pcrecookie} = [ $cookiepcre, $http_cookie_nocase ] if $cookiepcre;
 }

  $http_cookie=0 if $http_cookie;
  $cookiepcre=0 if $cookiepcre;

  next;
 }

#alert ip any any -> 103.13.232.232 any (msg:"Shadowserver C&C List: 103.13.232.232"; reference:url,rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt; classtype:misc-activity; sid:9990001; rev:1;)
 #elsif( $_=~ /^\s*alert\s+ip\s+\S+\s+\S+\s+\-\>\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d+)?)\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;[^\n]*?$referencesidrev/ )
 elsif( $_=~ /^\s*alert\s+ip\s+\S+\s+\S+\s+\-\>\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d+)?)\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;[^\n]*?$referencesidrev(?:[^\n]*$createdat)?/ )
 {
  if( $debug1 ){
   print "brut6: $_\n"; print "here6: 1: $1," if $1; print " 2: $2," if $2; print " 3: $3" if $3; print "\n";
  }
  #
  my $etmsg1=$2;
  my $remote_ip=$1;
  my $metadatacreatedyear=$3 if $3;
  #
 if( !@year2 || ($metadatacreatedyear && grep(/$metadatacreatedyear/, @year2)) )
 {
  print "remoteip6: $etmsg1, $remote_ip\n" if $debug1 && $remote_ip;
  print "metadata_created_year6: $etmsg1, $metadatacreatedyear\n" if $debug1 && $metadatacreatedyear;

  $hash{$etmsg1}{remoteip} = [ $remote_ip ] if $remote_ip;
  $hash{$etmsg1}{ametadatacreatedyear} = [ $metadatacreatedyear ] if $metadatacreatedyear;
 }

  $remote_ip=0 if $remote_ip;

  next;
 }

 else
 {
  print "signature parsing error: $_\n" if $debug1;
  next;
 }
}

print "####################################################################################\n" if $debug1;

my @threads = map threads->create(sub {
   #while (defined ( $_ = $queue->dequeue_nb()))  # for cat ... | perl etplc
   while ( defined ( $_ = $queue->dequeue()) ) {   # for tail -f ... | perl etplc

 chomp $_;
 $output_escape = printable($_);
 print "rawproxy: $output_escape\n" if $debug2;

 if ( $output_escape =~ /^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)?(?:\s(\S+)\s\S+\:\s)?(?:\#Software\: |\#Version\: |\#Start-Date\: |\#Date\: |\#Fields\: |\#Remark\: )/ ) {
  print "bypass BlueCoat/IIS headers.\n" if $debug2;
 }

# Squid default conf:
#2012-11-10T16:33:21.030867+01:00 hostname programname: 1352538457.034     79 192.168.2.3 TCP_MISS/200 2141 POST http://safe.google.com/downloads? - DIRECT/173.194.34.1 application/vnd.google.safe-update
#2012-11-10T16:33:21.031406+01:00 hostname programname: 1352538457.559     63 192.168.2.3 TCP_MISS/200 2688 GET http://safe-cache.google.com/safe/rd/ChNnb29ncIJyTBjIFl4kBAD8 - DIRECT/74.125.230.206 application/vnd.google.safebrowsing-chunk
#2012-11-10T16:33:21.031642+01:00 hostname programname: 1352538457.652    401 192.168.2.3 TCP_MISS/200 5472 CONNECT secure.infraton.com:443 - DIRECT/82.103.140.40 -
#2012-11-10T16:33:21.031658+01:00 hostname programname: 1352538457.776      4 192.168.2.3 TCP_MISS/404 449 GET http://89.9.8.8/ - DIRECT/89.9.8.8 text/html
#2012-11-10T16:33:21.032249+01:00 hostname programname: 1352538459.534     11 192.168.2.3 TCP_MISS/200 20207 GET http://safe-cache.google.com/safe/rd/ChFnohchAAGIGUDyCAqA8qugJVygMA______________________DzIPAcoDAP______9_____8P - DIRECT/74.125.230.206 application/vnd.google.safe-chunk
#2012-11-10T16:33:21.032448+01:00 hostname programname: 1352538486.175      0 192.168.2.3 TCP_MEM_HIT/200 2013 GET http://static.leboncoin.fr/img/logo.png - NONE/- image/png
#2012-11-10T16:33:21.035160+01:00 hostname programname: 1352538487.626    335 192.168.2.3 TCP_REFRESH_UNMODIFIED/200 80691 GET http://www.somantic.com/js/2010-07-01/adpan/google? - DIRECT/78.46.128.236 application/javascript
# without syslog header:
#1406207792.966 120930 192.168.8.3 TCP_MISS/200 111285 CONNECT https://i1.ytimg.com:443 - DEFAULT_PARENT/127.0.0.1 -
 #if ( $output_escape =~ /^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)\s(\S+)\s\S+\:\s(\d+\.\d+)\s+\d+\s+(\S+)\s+[A-Z\_]+\/(\d+)\s\d+\s+([A-Z]+)\s+(\S+)\s+\-\s+[A-Z]+\/(\S+)\s/ ) {
# elsif ( $output_escape =~ /^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)?(?:\s(\S+)\s\S+\:\s)?(\d+\.\d+)\s+\d+\s+(\S+)\s+[A-Z\_]+\/(\d+)\s\d+\s+([A-Z]+)\s+(\S+)\s+\-\s+[A-Z\_]+\/(\S+)\s/ ) {
 elsif ( $output_escape =~ /^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)?(?:\s(\S+)\s\S+\:\s)?(\d+\.\d+)\s+\d+\s+(\S+)\s+[A-Z\_]+\/(\d+)\s\d+\s+([A-Z]+)\s+(?:[^\:]*?\:\/\/)?([^\/]*?)(\/\S*)?\s+\-\s+[A-Z\_]+\/(\S+)\s/ ) {
#  $timestamp_central=$1; $server_hostname_ip=$2; $timestamp_unix=$3; $client_hostname_ip=$4; $http_reply_code=$5; $client_http_method=$6; $client_http_uri=$7; $web_hostname_ip=$8;
  $timestamp_central=$1; $server_hostname_ip=$2; $timestamp_unix=$3; $client_hostname_ip=$4; $http_reply_code=$5; $client_http_method=$6; $client_http_host=$7; $client_http_uri=$8; $web_hostname_ip=$9;
  $client_username="";
  unless( $1 ) { $timestamp_central="N/A" }
  unless( $2 ) { $server_hostname_ip="N/A" }
  print "passage dans squid default regexp.\n" if $debug2;
 }

# Squid added User-Agent:
#<179>Jan  9 00:05:34 hostname programname:   180 192.168.1.2 TCP_MISS/200 - [09/Jan/2013:00:05:25 +0100] 24375 GET http://www.mag-securs.com/images/Alertes_V2.jpg - DIRECT/93.93.190.66 image/jpeg \"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:18.0) Gecko/20100101 Firefox/18.0\" \"http://www.mag-securs.com/articleId.aspx\"
#<179>Jan  8 23:42:32 hostname programname:   190 192.168.1.2 TCP_MISS/200 - [08/Jan/2013:23:42:24 +0100] 2109 GET http://www.mag-securs.com/BorderLayout.css - DIRECT/93.93.190.66 text/css \"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:18.0) Gecko/20100101 Firefox/18.0\" \"http://www.mag-securs.com/\"
#2013-01-08T23:44:33.020912+01:00 hostname programname: 134640 192.168.1.2 TCP_MISS/200 - [08/Jan/2013:23:44:24 +0100] 30922 CONNECT www.google.fr:443 - DIRECT/173.194.34.55 - \"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:18.0) Gecko/20100101 Firefox/18.0\" \"-\"
#2013-11-23T21:31:02.669653+01:00 hostname programname:     2 192.168.1.2 TCP_MISS/503 - [23/Nov/2013:21:30:58 +0100] 0 CONNECT www.marketscore.com:443 - HIER_NONE/- - "Wget/1.13.4 (linux-gnu)" "-" "-"
#2013-01-07T22:17:39.350724+01:00 hostname programname:    11 192.168.2.3 TCP_REFRESH_UNMODIFIED/304 - [07/Jan/2013:22:17:34 +0100] 286 GET http://mscrl.microsoft.com/pki/mscorp/crl/Microsoft%20Secure%20Server%20Authority(8).crl - DIRECT/94.245.70.118 application/pkix-crl \"Microsoft-CryptoAPI/6.0\" \"-\"
#2013-01-07T22:17:09.324890+01:00 hostname programname:   397 192.168.2.3 TCP_MISS/200 - [07/Jan/2013:22:17:03 +0100] 10945 GET http://appldnld.apple.com/iOS6/CarrierBundles/0ge_France_iPhone.ipcc - DIRECT/2.22.48.115 application/octet-stream \"iTunes/11.0.1 (Windows; Microsoft Windows Vista Home Premium Edition Service Pack 1 (Build 6001)) AppleWebKit/536.27.1\" \"-\"
#2013-01-07T21:30:26.791289+01:00 hostname programname:     1 192.168.2.3 TCP_MEM_HIT/200 - [07/Jan/2013:21:30:22 +0100] 15755 GET http://ax.init.itunes.apple.com/bag.xml? - NONE/- text/xml \"iTunes/11.0.1 (Windows; Microsoft Windows Vista Home Premium Edition Service Pack 1 (Build 6001)) AppleWebKit/536.27.1\" \"-\"
#2013-06-12T21:47:06.261557+02:00 hostname programname:   332 192.168.1.2 TCP_MISS/000 - [12/Jun/2013:21:46:57 +0200] 0 GET http://1.1.1.112/%67gu.php - DIRECT/1.1.1.112 - \"Wget/1.13.4 (linux-gnu)\" \"-\"
#2013-06-12T21:58:26.751411+02:00 hostname programname:   288 192.168.1.2 TCP_MISS/000 - [12/Jun/2013:21:58:23 +0200] 0 GET http://1.1.1.112/%67gu.php - DIRECT/1.1.1.112 - "Wget/1.13.4 (linux-gnu)" "-"
# add cookie + remote_ip :
# 2013-11-23T02:09:29.909623+01:00 hostname programname:   142 192.168.1.2 TCP_MISS/200 - [23/Nov/2013:02:09:22 +0100] 1890 GET http://etplc.org/ - HIER_DIRECT/etplc.org text/html "Wget/1.13.4 (linux-gnu)" "-" "fGGhTasdas=http" 8.8.8.8

# elsif ( $output_escape =~ /^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)?(?:\s(\S+)\s\S+\:\s+)?\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+[A-Z\_]+\/(\d+)\s+\-\s+\[(.*?)\]\s+\d+\s+([^\s]+)\s([^\s]+)\s\-\s[^\/]+\/([^\s]+)\s[^\s]+\s\\\"([^\"]+)\\\" \\\"([^\"]+)\\\" \\\"([^\"]+)\\\"(?:\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?/ ) {
 elsif ( $output_escape =~ /^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)?(?:\s(\S+)\s\S+\:\s+)?\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+[A-Z\_]+\/(\d+)\s+\-\s+\[(.*?)\]\s+\d+\s+(\S+)\s(?:[^\:]*?\:\/\/)?([^\/]*?)(\/\S*)?\s\-\s[^\/]+\/([^\s]+)\s[^\s]+\s\\\"([^\"]+)\\\" \\\"([^\"]+)\\\" \\\"([^\"]+)\\\"(?:\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?/ ) {
#  $timestamp_central=$1; $server_hostname_ip=$2; $client_hostname_ip=$3; $http_reply_code=$4; $timestamp_unix=$5; $client_http_method=$6; $client_http_uri=$7; $web_hostname_ip=$8; $client_http_useragent=$9; $client_http_referer=$10; $client_http_cookie=$11; $server_remote_ip=$12;
  $timestamp_central=$1; $server_hostname_ip=$2; $client_hostname_ip=$3; $http_reply_code=$4; $timestamp_unix=$5; $client_http_method=$6; $client_http_host=$7; $client_http_uri=$8; $web_hostname_ip=$9; $client_http_useragent=$10; $client_http_referer=$11; $client_http_cookie=$12; $server_remote_ip=$13;
  $client_username="";
  unless( $1 ) { $timestamp_central="N/A" }
  unless( $2 ) { $server_hostname_ip="N/A" }
  print "passage dans squid added User-Agent regexp.\n" if $debug2;
 }

# Default and Custom Apache log:
#<179>Jan 11 22:27:22 hostname programname: 1.1.1.1 - - [11/Jan/2013:22:27:16 +0100] \"GET /index.html HTTP/1.1\" 200 426 \"-\" \"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:18.0) Gecko/20100101 Firefox/18.0\"
#<179>Jan 11 22:45:23 hostname programname: 1.1.1.1 - - [11/Jan/2013:22:45:14 +0100] \"GET /hourly.png HTTP/1.1\" 200 11363 \"http://1.1.1.111/abc.html\" \"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:18.0) Gecko/20100101 Firefox/18.0\"
#<179>Jan 11 23:01:49 hostname programname: 1.1.1.1 - - [11/Jan/2013:23:01:42 +0100] \"GET /abc.exe HTTP/1.1\" 404 230 \"-\" \"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:18.0) Gecko/20100101 Firefox/18.0\"
#<179>Jan 12 11:24:25 hostname programname: 1.1.1.1 - - [12/Jan/2013:11:24:17 +0100] \"GET /home_all.png HTTP/1.1\" 304 - \"http://1.1.1.111/abc.pl\" \"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:18.0) Gecko/20100101 Firefox/18.0\"
#2013-11-26T22:39:16.387745+01:00 hostname programname: 142.4.198.179 - - [26/Nov/2013:22:39:07 +0100] "GET /muieblackcat HTTP/1.1" 404 218
# add referer + user-agent + cookie :
# 2013-11-22T22:01:49.577030+01:00 hostname programname: 1.1.1.11 - - [22/Nov/2013:22:01:48 +0100] "GET / HTTP/1.1" 200 1564 "-" "Wget/1.13.4 (linux-gnu)" "fGGhTasdas=http"
# apache logs:
# 127.0.0.1 - - [05/Dec/2014:10:33:40 +0100] "GET /linux/ HTTP/1.1" 200 3713 "http://localhost/" "Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0" "cookie=1"
#
# 1.1.1.1 - user [23/Mar/2014:07:41:08 +0100] "GET http://test.com/ont.woff HTTP/1.1" 200 27533 "http://www.referer.com/style.css" "Mozilla/5.0 (Windows NT 5.1; rv:27.0) Gecko/20100101 Firefox/27.0" TCP_MEM_HIT:HIER_NONE text/plain 261 - - "URL category ALL is ALLOWED"
#

 elsif ( $output_escape =~ /^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)?(?:\s(\S+)\s\S+\:\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\-\s+(\S+)\s+\[([^\]]*?)\]\s+\\\"([^\s]+)\s(\S+)\s\S+\\\"\s(\d+)\s(?:\d+|\-)(?:\s\\\"(.*?)\\\")?(?:\s\\\"(.*?)\\\")?(?:\s\\\"(.*?)\\\")?/ ) {
  $timestamp_central=$1; $server_hostname_ip=$2; $client_hostname_ip=$3; $client_username=$4; $timestamp_unix=$5; $client_http_method=$6; $client_http_uri=$7; $http_reply_code=$8; $client_http_referer=$9; $client_http_useragent=$10; $client_http_cookie=$11;
  if( $client_username eq "-" ){ $client_username="" }
  print "passage dans Apache regexp.\n" if $debug2;
 }

# log proxy TMG/FOREFRONT:
# 10.0.0.1     DOMAINE\USERNAME     Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)     2013-07-21      00:00:00        SERVERNAME      http://abc.com/abcd       -       10.0.0.2  8080    4493    625     291     http    GET     http://abc.com/def     Upstream	200
#10.0.0.1     anonymous       Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) 2013-07-21      00:00:12        SERVERNAME      http://www.google.com/22	855560    www.google.com  10.0.0.2     8085    1       1112    4587    http    GET     http://www.google.com/ -	12209
#10.0.0.1      anonymous       Microsoft-CryptoAPI/6.1 2013-07-21      04:54:20        SERVERNAME      -       rapidssl-crl.geotrust.com       10.0.0.2     8085    1       180     4587    http	GET     http://rapidssl-crl.geotrust.com/crls/rapidssl.crl      -       12209
#10.0.0.1\tanonymous\tMozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)\t2013-07-21\t00:01:06\tSERVERNAME\t-\t-\t10.0.0.2\t443\t0\t0\t544\tSSL-tunnel\t-\tmail.google.com:443\tInet\t407
#10.0.0.1	DOMAINE\USERNAME	Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)	2013-06-21	00:00:13	SERVERNAME	-	-	10.0.0.2	8085	0	1695	1532	SSL-tunnel	-	www.marketscore.com:443	Upstream	0
#10.0.0.1	DOMAINE\USERNAME	Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)	2013-06-21	00:00:24	SERVERNAME	-	www.marketscore.com	10.0.0.2	443	31	938	448	SSL-tunnel	CONNECT	-	-	12210

#elsif ( $output_escape =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\t|\\t)+(\S+)(?:\t|\\t)+(.*?)(?:\t|\\t)+(\d{4}\-\d{2}\-\d{2})(?:\t|\\t)+(\d{2}\:\d{2}\:\d{2})(?:\t|\\t)+([0-9a-zA-Z\-\_]+)(?:\t|\\t)+(.*?)(?:\t|\\t)+(.*?)(?:\t|\\t)+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+.*?(?:\t|\\t)+([0-9a-zA-Z\-\_]+)(?:\t|\\t)+(?:\w+\:\/\/)?([^\/]*?)(\/.*?)?(?:\t|\\t)+\S+(?:\t|\\t)+(\d+)/) {
 elsif ( $output_escape =~ /^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)?(?:\s(\S+)\s\S+\:\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\t|\\t)+(\S+)(?:\t|\\t)+(.*?)(?:\t|\\t)+(\d{4}\-\d{2}\-\d{2})(?:\t|\\t)+(\d{2}\:\d{2}\:\d{2})(?:\t|\\t)+([0-9a-zA-Z\-\_]+)(?:\t|\\t)+(.*?)(?:\t|\\t)+(.*?)(?:\t|\\t)+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+.*?(?:\t|\\t)+([0-9a-zA-Z\-\_]+)(?:\t|\\t)+(?:\w+\:\/\/)?([^\/]*?)(\/.*?)?(?:\t|\\t)+\S+(?:\t|\\t)+(\d+)/) {
# $client_hostname_ip=$1; $client_username=$2; $client_http_useragent=$3; $timestamp_central=$4." ".$5; $server_hostname_ip=$6; $client_http_referer=$7; $client_http_method=$9; $client_http_host=$10; $client_http_uri=$11; $http_reply_code=$12;
  $timestamp_central=$1; $server_hostname_ip=$2; $client_hostname_ip=$3; $client_username=$4; $client_http_useragent=$5; $timestamp_central=$6." ".$7; $server_hostname_ip=$8; $client_http_referer=$9; $client_http_method=$11; $client_http_host=$12; $client_http_uri=$13; $http_reply_code=$14;
  # https/ssl-tunnel:
  #if( $13 eq "-" && $10 ne "-" )
  #{
  # $client_http_uri=$10;
  #}
  unless( $1 ) { $timestamp_central=$6." ".$7 }
  unless( $2 ) { $server_hostname_ip=$8 }
  print "passage dans TMG/ForeFront regexp.\n" if $debug2;
 }

# log proxy BlueCoat sans http_method:
# <161>Aug 21 21:59:59 srv log: 2014-08-21 22:00:00 2 10.0.0.2 - - "none" PROXIED 407 - TCP_DENIED - http tools.google.com 80 /service/update2 ?w=6 "Google Update" 10.0.0.3 1681 1665 -

 elsif ( $output_escape =~ /^(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(\S+)\s)?(?:\S+\:\s)?(\d{4}\-\d{2}\-\d{2})\s(\d{2}\:\d{2}\:\d{2})\s\d+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\S+)\s(?:\-|\S+)\s\\\"[^\"]*?\\\"\s\S+\s(\d+)\s(\S+)\s\S+\s\S+\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(?:\\\"([^\"]*?)\\\"|(\-))\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d+\s\d+\s\-\s?\\?r?$/ ) {
  #$server_hostname_ip=$1; $timestamp_central=$2." ".$3; $client_hostname_ip=$4; $client_username=$5; $http_reply_code=$6; $client_http_referer=$7; $client_http_uri="$8:\/\/$9$11$12"; $client_http_useragent=$13;
  $server_hostname_ip=$1; $timestamp_central=$2." ".$3; $client_hostname_ip=$4; $client_username=$5; $http_reply_code=$6; $client_http_referer=$7; $client_http_host=$9; $client_http_uri="$11$12"; $client_http_useragent=$13;
  #if( $8 eq "tcp" && $12 ne "-" ) { $client_http_uri=$9 }
  unless( $13 ) { $client_http_useragent=$14 }
  #if( $12 eq "-" && $8 ne "tcp" ) { $client_http_uri="$8:\/\/$9$11" }
  if( $12 eq "-" && $8 ne "tcp" ) { $client_http_uri="$11" }
  #elsif( $12 eq "-" && $8 eq "tcp" ) { $client_http_uri="$9$11" }
  elsif( $12 eq "-" && $8 eq "tcp" ) { $client_http_uri="$11" }
  print "passage dans BlueCoat 1 sans http_method regexp.\n" if $debug2;
 }


# log proxy BlueCoat avec http_method:
# Fields: (syslog header)           date       time  time-taken c-ip cs-username cs-auth-group cs-categories sc-filter-result sc-status cs(Referer) s-action rs(Content-Type) cs-method cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs(User-Agent) s-ip sc-bytes cs-bytes x-virus-id
# Jan 10 11:10:21 10.0.0.1/10.0.0.1 2013-10-10 11:10:21 68 10.0.0.2 - - \"bc_rules\" CATEGORY 304 http://referer.com TCP_HIT image/gif GET http www.test.com 80 /path.gif - \"Mozilla/4.0\" 10.0.0.3 370 665 -
# Oct 10 11:10:21 10.0.0.1/10.0.0.1 2013-10-10 11:10:22 135 10.0.0.2 user group \"none\" CATEGORY 200 http://referer.com TCP_CLIENT_REFRESH application/javascript GET http www.test.com 80 /path.js - \"Mozilla/4.0\" 10.0.0.3 22159 568 -
# Oct 10 11:10:21 10.0.0.1/10.0.0.1 2013-10-10 11:10:23 15 10.0.0.2 user group \"none\" CATEGORY 204 - TCP_NC_MISS text/html GET http www.test.com 80 /path ?arg=1 \"Mozilla/4.0\" 10.0.0.3 321 491 -
# Oct 10 11:10:21 10.0.0.1/10.0.0.1 2013-10-10 11:10:24 1 10.0.0.2 - - \"none\" CATEGORY 407 - TCP_DENIED - CONNECT tcp www.test.com 443 / - \"Mozilla/4.0\" 10.0.0.3 330 308 -

 elsif ( $output_escape =~ /^(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(\S+)\s)?(?:\S+\:\s)?(\d{4}\-\d{2}\-\d{2})\s(\d{2}\:\d{2}\:\d{2})\s\d+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\S+)\s(?:\-|\S+)\s\\\"[^\"]*?\\\"\s\S+\s(\d+)\s(\S+)\s\S+\s\S+\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(?:\\\"([^\"]*?)\\\"|(\-))\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d+\s\d+\s\-\s?\\?r?$/ ) {
  #$server_hostname_ip=$1; $timestamp_central=$2." ".$3; $client_hostname_ip=$4; $client_username=$5; $http_reply_code=$6; $client_http_referer=$7; $client_http_method=$8; $client_http_uri="$9:\/\/$10$12$13"; $client_http_useragent=$14;
  $server_hostname_ip=$1; $timestamp_central=$2." ".$3; $client_hostname_ip=$4; $client_username=$5; $http_reply_code=$6; $client_http_referer=$7; $client_http_method=$8; $client_http_host=$10; $client_http_uri="$12$13"; $client_http_useragent=$14;
  #if( $9 eq "tcp" && $13 ne "-" ) { $client_http_uri=$10 }
  unless( $13 ) { $client_http_useragent=$14 }
  #if( $13 eq "-" && $9 ne "tcp" ) { $client_http_uri="$9:\/\/$10$12" }
  if( $13 eq "-" && $9 ne "tcp" ) { $client_http_uri="$12" }
  #elsif( $13 eq "-" && $9 eq "tcp" ) { $client_http_uri="$10$12" }
  elsif( $13 eq "-" && $9 eq "tcp" ) { $client_http_uri="$12" }
  print "passage dans BlueCoat 2 avec http_method regexp.\n" if $debug2;
 }


# Format MAIN SGOS v6.5.5.5
#Fields: date time time-taken c-ip sc-status s-action sc-bytes cs-bytes cs-method cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs-username cs-auth-group s-supplier-name rs(Content-Type) cs(Referer) cs(User-Agent) sc-filter-result cs-categories x-virus-id s-ip
#2014-12-27 19:32:40 306 10.0.0.1 200 TCP_ACCELERATED 39 213 CONNECT tcp snippets.mozilla.com 443 / - - - 172.16.0.1 - - "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:20.0) Gecko/20130416 Firefox/20.0" OBSERVED "Technology/Internet" - 172.16.0.1
#2014-12-27 19:32:40 70 10.0.0.1 200 TCP_NC_MISS 1665 512 POST http gtssl-ocsp.geotrust.com 80 / - - - gtssl-ocsp.geotrust.com application/ocsp-response - "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:20.0) Gecko/20130416 Firefox/20.0" OBSERVED "Technology/Internet" - 172.16.0.1
#2014-12-27 19:36:58 27 10.0.0.1 200 TCP_NC_MISS 411 731 GET http www.google.fr 80 /6407654/ ?label=All - - www.google.fr image/gif http://www.test.fr/ "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:20.0) Gecko/20130416 Firefox/20.0" OBSERVED "Search Engines/Portals" - 172.16.0.1
#2014-12-27 19:36:59 1 10.0.0.1 0 DENIED 0 0 unknown ssl webanalytics.btelligent.net 443 / - - - webanalytics.btelligent.net - - - DENIED "Placeholders" - 172.16.0.1

 elsif ( $output_escape =~ /^(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(\S+)\s)?(?:\S+\:\s)?(\d{4}\-\d{2}\-\d{2})\s(\d{2}\:\d{2}\:\d{2})\s\d+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\d+)\s\S+\s\d+\s\d+\s(\S+)\s(\S+)\s(\S+)\s(\d+)\s(\S+)\s(\S+)\s(\S+)\s\S+\s\S+\s\S+\s(\S+)\s(?:\\\"([^\"]*?)\\\"|(\-))\s\S+\s(?:\\\"(?:[^\"]*?)\\\"|(?:\-))\s(?:\\\"(?:[^\"]*?)\\\"|(?:\-))\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\\r)?$/ ) {
  #$server_hostname_ip=$1; $timestamp_central=$2." ".$3; $client_hostname_ip=$4; $http_reply_code=$5; $client_http_method=$6; $client_http_uri="$7:\/\/$8$10$11"; $client_username=$12; $client_http_referer=$13; $client_http_useragent=$14; $server_remote_ip=$16;
  $server_hostname_ip=$1; $timestamp_central=$2." ".$3; $client_hostname_ip=$4; $http_reply_code=$5; $client_http_method=$6; $client_http_host=$8; $client_http_uri="$10$11"; $client_username=$12; $client_http_referer=$13; $client_http_useragent=$14; $server_remote_ip=$16;
  #if( $7 eq "tcp" ) { $client_http_uri=$8 }
  #if( $11 eq "-" && $7 ne "tcp" ) { $client_http_uri="$7:\/\/$8$10" }
  if( $11 eq "-" && $7 ne "tcp" ) { $client_http_uri="$10" }
  #elsif( $11 eq "-" && $7 eq "tcp" ) { $client_http_uri="$8$10" }
  elsif( $11 eq "-" && $7 eq "tcp" ) { $client_http_uri="$10" }
  print "passage dans BlueCoat 3 avec http_method regexp.\n" if $debug2;
 }


# BlueCoat:
#Feb 12 10:55:06 10.33.243.105 #Fields: date time s-ip sc-filter-result sc-status s-action x-timestamp-unix-utc cs-bytes sc-bytes x-cs-http-version x-sc-http-status cs-protocol cs-host c-uri cs-uri-port cs-uri-path cs-categories c-ip c-port s-port cs-userdn x-cs-user-authorization-name s-icap-info s-icap-status cs(User-Agent) s-connect-type cs-method x-cs-http-method rs(Content-Type) r-ip
#Mar  6 12:07:41 host 2015-03-06 11:07:42 10.0.0.1 OBSERVED 200 TCP_NC_MISS 1425640062 748 8347 1.1 200 http www.test.com http://www.test.com/wiki?abc 80 /wiki "cat" 10.1.1.1 50455 8080 cn=x,o=y cn=a,o=y - ICAP "UA" Direct GET GET text/html;%20charset=UTF-8 1.1.1.1
#Mar  6 12:07:41 host 2015-03-06 11:07:42 10.0.0.1 OBSERVED 0 TUNNELED 1425640062 1874 818 - - ssl google.com ssl://google.com:443/ 443 / "cat1;cat2" 10.1.1.1 62243 8000 - - - ICAP - Direct unknown - - 1.1.1.1
#Mar  6 12:07:41 host 2015-03-06 11:07:41 10.0.0.1 DENIED 404 TCP_ERR_MISS 1425640061 194 7616 1.1 404 http web.com http://web.com/test.php?abc=def 80 /test.php "cat1;cat2" 10.1.1.1 4107 8080 - - - ICAP - Error GET GET - -
#Mar  6 12:08:35 host 2015-03-06 11:08:36 10.0.0.1 DENIED 503 TCP_ERR_MISS 1425640116 489 7646 1.1 503 http test.com http://test.com/z.gif?abc 80 /z.gif "cat1" 10.1.1.1 49683 8080 cn=x cn=a - ICAP "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:17.0) Gecko/20100101" Direct GET GET - 2a01:c9c0:b6:170::43
#Mar  6 12:09:58 host 2015-03-06 11:09:59 10.0.0.1 OBSERVED 200 TCP_NC_MISS 1425640199 1846 629885417 1.1 200 http test.com http://test.com/abc 80 /abc "cat" 10.1.1.1 51278 8080 cn=x cn=a "icap..." ICAP "Mozilla" Direct GET GET appli/abc 1.1.1.1

 #elsif ( $output_escape =~ /^(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(?:\S+)\s)?(?:\S+\:\s)?(\d{4}\-\d{2}\-\d{2}\s\d{2}\:\d{2}\:\d{2})\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s[A-Z]+\s(\d+)\s\S+\s\d+\s\d+\s\d+\s\S+\s(?:\d+|\-)\s\S+\s(\S+)\s(?:\w+\:\/\/[^\/]*?)(\/\S*)\s\d+\s\S+\s(?:\\\"(?:[^\"]*?)\\\"|(?:\-))\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s\d+\s\d+\s\S+\s\S+\s\S+\s\S+\s(?:\\\"([^\"]*?)\\\"|(\-))\s\S+\s(\S+)\s\S+\s\S+\s(?:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(\-))(?:\\r)?$/ ) {
 elsif ( $output_escape =~ /^(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(?:\S+)\s)?(?:\S+\:\s)?(\d{4}\-\d{2}\-\d{2}\s\d{2}\:\d{2}\:\d{2})\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s[A-Z]+\s(\d+)\s\S+\s\d+\s\d+\s\d+\s\S+\s(?:\d+|\-)\s\S+\s(\S+)\s(?:\w+\:\/\/[^\/]*?)(\/\S*)\s\d+\s\S+\s(?:\\\"(?:[^\"]*?)\\\"|(?:\-))\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s\d+\s\d+\s\S+\s\S+\s(?:\\\"(?:[^\"]*?)\\\"|(?:\S+))\s\S+\s(?:\\\"([^\"]*?)\\\"|(\-))\s\S+\s(\S+)\s\S+\s\S+\s(?:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(\-)|(?:\S+))(?:\\r)?$/ ) {
  $timestamp_central=$1; $server_hostname_ip=$2; $http_reply_code=$3; $client_http_host=$4; $client_http_uri=$5; $client_hostname_ip=$6; $client_http_useragent=$7; $client_http_method=$9; $server_remote_ip=$10;
  if( $10 && $10 eq "-" ) { $client_http_useragent="-" }
  if( $11 && $11 eq "-" ) { undef $server_remote_ip }
  print "passage dans BlueCoat 4 regexp.\n" if $debug2;
 }


# BlueCoat Bernie:
#"date","time","time_taken","c_ip", "cs_username","cs_auth_group","x_exception_id","sc_filter_result","cs_categories",    "cs_referer","sc_status","s_action", "cs_method","rs_content_type", "cs_uri_scheme","cs_host",     "cs_uri_port","cs_uri_path",                "cs_uri_query","cs_uri_extension","cs_user_agent",  "s_ip",  "sc_bytes","cs_bytes","x_virus_id","x_bluecoat_application_name","x_bluecoat_application_operation"
#2015-04-08 17:48:33 215 123.321.0.1 username     Domain\OU       -                OBSERVED           "Audio/Video Clips" -            200         TCP_NC_MISS POST        application/x-fcs  http            111.123.24.100 80            /idle/GTKmdz02ySLKCn_Z/153489 -              -                  "Shockwave Flash" 10.0.0.5 1930       220        -            "none"                        "none"
 elsif ( $output_escape =~ /^(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(\S+)\s)?(?:\S+\:\s)?(\d{4}\-\d{2}\-\d{2})\s(\d{2}\:\d{2}\:\d{2})\s\d+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\S+)\s\S+\s\S+\s\S+\s\\\"[^\"]*?\\\"\s(?:\\\"([^\"]*?)\\\"|(\-))\s(\d+)\s\S+\s(\S+)\s\S+\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s\S+\s(?:\\\"([^\"]*?)\\\"|(\-))\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s\d+\s\d+\s\-\s\\\"[^\"]*?\\\"\s\\\"[^\"]*?\\\"\s?\\?r?$/) {
  $server_hostname_ip=$1; $timestamp_central=$2." ".$3; $server_remote_ip=$4; $client_username=$5; $client_http_referer=$6; $http_reply_code=$8; $client_http_method=$9; $client_http_host=$11; $client_http_uri="$13$14"; $client_http_useragent=$15; $client_hostname_ip=$17;
  unless($6) {$client_http_referer=$7}
  if( $14 eq "-" && $10 ne "tcp" ) { $client_http_uri="$13" }
  elsif( $14 eq "-" && $10 eq "tcp" ) { $client_http_uri="$13" }
  print "passage dans BlueCoat 5 regexp.\n" if $debug2;
 }


# BlueCoat:
#Fields: date time time-taken c-ip sc-status s-action sc-bytes cs-bytes cs-method cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs-username cs-auth-group s-hierarchy s-supplier-name rs(Content-Type) cs(Referer) cs(User-Agent) sc-filter-result cs-categories x-virus-id s-ip
#<syslog> 2015-05-31 00:00:08 7 192.168.0.1 200 TCP_NC_MISS 265 400 HEAD http test.com 80 /index.php ?a=b user group - test.com application/php http://referer.com/a.php?d=e "Mozilla/4.0" OBSERVED "Category" - 192.168.0.2
#<syslog> 2015-05-31 00:00:10 62304 192.168.0.1 200 TCP_TUNNELED 4398 4626 CONNECT tcp test.com 443 / - user group - 192.168.0.2 - - "Mozilla/4.0" OBSERVED "Category" - 192.168.0.2
 elsif ( $output_escape =~ /^(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(\S+)\s)?(?:\S+\:\s)?(\d{4}\-\d{2}\-\d{2})\s(\d{2}\:\d{2}\:\d{2})\s\d+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\S+)\s\S+\s\d+\s\d+\s(\S+)\s(\S+)\s(\S+)\s\d+\s(\S+)\s(\S+)\s(\S+)\s\S+\s\S+\s\S+\s\S+\s(\S+)\s(?:\\\"([^\"]*?)\\\"|(\-))\s\S+\s\\\"[^\"]*?\\\"\s\S+\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\\r)?$/) {
  $server_hostname_ip=$1; $timestamp_central=$2." ".$3; $client_hostname_ip=$4; $http_reply_code=$5; $client_http_method=$6; $client_http_host=$8; $client_http_uri="$9$10"; $client_username=$11; $client_http_referer=$12; $client_http_useragent=$13; $client_hostname_ip=$14;
  if( $10 eq "-" && $7 ne "tcp" ) { $client_http_uri="$9" }
  elsif( $10 eq "-" && $7 eq "tcp" ) { $client_http_uri="$9" }
  print "passage dans BlueCoat 6 regexp.\n" if $debug2;
 }


# log proxy McAfee WebGateway default v7.2.x (missing Referer and Cookie)
# [1/Mar/2014:17:34:07 +0200] \"\" \"\" 10.1.1.1 200 \"POST http://google.com/test?test HTTP/1.1\" \"Category\" \"0 (Minimal Risk)\" \"text/xml\" 818 \"Java/1.6.0_55\" \"McAfeeGW: Optionnal Antivirus\" Cache=\"TCP_MISS_RELOAD\" nexthopname.com
# [1/Mar/2014:17:34:07 +0200] \"dom\\alloa\" \"Policyname\" 10.1.1.1 200 \"GET http://1.1.1.1/abc/def/ghi HTTP/1.1\" \"Content Server, Social Networking\" \"-24 (Unverified)\" \"application/x-fcs\" 270 \"Shockwave Flash\" \"\" Cache=\"TCP_MISS_VERIFY\" nexthopname.com
# [1/Mar/2014:17:34:11 +0200] \"\" \"\" 10.1.1.1 200 \"CONNECT ssl.google-analytics.com:443 HTTP/1.1\" \"Internet Services\" \"3 (Minimal Risk)\" \"\" 6847 \"Mozilla/5.0 (compatible; MSIE 11.0; Windows NT 7.1; Trident/5.0)\" \"\" Cache=\"TCP_MISS\" nexthopname.com
# 2013-11-22T22:01:49.577030+01:00 hostname programname: [1/Mar/2014:17:34:11 +0200] \"\" \"\" 10.1.1.1 200 \"CONNECT ssl.google-analytics.com:443 HTTP/1.1\" \"Internet Services\" \"3 (Minimal Risk)\" \"\" 6847 \"Mozilla/5.0 (compatible; MSIE 11.0; Windows NT 7.1; Trident/5.0)\" \"\" Cache=\"TCP_MISS\" nexthopname.com

 #elsif ( $output_escape =~ /^(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(\S+)\s)?(?:\S+\:\s)?\s*\[([^\]]*?)\] \\\"([^\"]*?)\\\" \\\"[^\"]*?\\\" (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (0|\d{3}) \\\"([^\s]+)\s([^\s]+)\s[^\"]*?\\\" \\\"[^\"]*?\\\" \\\"[^\"]*?\\\" \\\"[^\"]*?\\\" \d+ \\\"([^\"]*)\\\" \\\"[^\"]*?\\\" \S+ (?:\S+)?$/ ) {
 elsif ( $output_escape =~ /^(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(\S+)\s)?(?:\S+\:\s)?\s*\[([^\]]*?)\] \\\"([^\"]*?)\\\" \\\"[^\"]*?\\\" (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (0|\d{3}) \\\"([^\s]+)\s(?:\w+\:\/\/)?([^\/]*?)(\/[^\s]*)?\s[^\"]*?\\\" \\\"[^\"]*?\\\" \\\"[^\"]*?\\\" \\\"[^\"]*?\\\" \d+ \\\"([^\"]*)\\\" \\\"[^\"]*?\\\" \S+ (?:\S+)?$/ ) {
  #$server_hostname_ip=$1; $timestamp_central=$2; $client_username=$3; $client_hostname_ip=$4; $http_reply_code=$5; $client_http_method=$6; $client_http_uri=$7; $client_http_useragent=$8;
  $server_hostname_ip=$1; $timestamp_central=$2; $client_username=$3; $client_hostname_ip=$4; $http_reply_code=$5; $client_http_method=$6; $client_http_host=$7; $client_http_uri=$8; $client_http_useragent=$9;
  unless( $client_http_useragent ) { $client_http_useragent="-" }
  print "passage dans McAfee default regexp.\n" if $debug2;
 }


# log IIS webserver default v7.5 (missing Cookie)
#Fields: date time s-sitename s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken
# 2015-01-20 08:48:18 W3SVC NFOR 172.31.20.200 GET /_common/media/img/P_Niv3.gif - 80 - 10.94.210.10 Mozilla/5.0+(Windows+NT+6.1;+WOW64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/39.0.2171.99+Safari/537.36 https://test.fr/_common/css/WDDesignns.css 304 0 0 210 909 15
# 2015-01-23 15:45:19 W3SVC2 DOFR01 10.0.0.2 GET /download/downloadUrl.asp file=../../../../../../../etc/passwd 80 - 10.94.210.10 Mozilla/5.0+(X11;+Linux+x86_64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/39.0.2171.95+Safari/537.36 - 200 0 0 195 847 31
# 2015-01-23 15:50:53 W3SVC2 DOFR01 10.0.0.2 GET /download/downloadUrl.asp file=../../etc/passwd 80 - 10.94.210.10 Mozilla/5.0+(Macintosh;+Intel+Mac+OS+X+10_10_1)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/39.0.2171.95+Safari/537.36 - 200 0 0 195 818 15

 elsif ( $output_escape =~ /^(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(\S+)\s)?(?:\S+\:\s)?(\d{4}\-\d{2}\-\d{2} \d{2}\:\d{2}\:\d{2})\s(\S+)\s(\S+)\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s(\S+)\s(\S+)\s(\S+)\s(\d+)\s(\S+)\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\S+)\s(\S+)\s(\d+)\s\d+\s\d+\s\d+\s\d+\s\d+/ ) {
  #$timestamp_central=$2; $server_hostname_ip=$4; $client_http_method=$5; $client_http_uri=":\/\/$3$6"; $client_username=$9; $client_hostname_ip=$10; $client_http_useragent=$11; $client_http_referer=$12; $http_reply_code=$13;
  $timestamp_central=$2; $server_hostname_ip=$4; $client_http_method=$5; $client_http_host=$3; $client_http_uri=$6; $client_username=$9; $client_hostname_ip=$10; $client_http_useragent=$11; $client_http_referer=$12; $http_reply_code=$13;
  #if( $8 eq "443" ) { $client_http_uri="https$client_http_uri" }
  #else { $client_http_uri="http$client_http_uri" }
  unless( $7 eq "-" ) { $client_http_uri="$client_http_uri?$7" }
  $client_http_useragent =~ s/\+/ /g;
  if( $client_username eq "-" ){ $client_username="" }
  print "passage dans IIS default regexp.\n" if $debug2;
 }

# WebSense:
#Apr 27 10:10:10 10.0.0.1 vendor=Websense product=Security product_version=1.1.1 action=permitted severity=1 category=1 user="ou=a ou=b" src_host=10.0.0.2 src_port=1025 dst_host=www.google.com dst_ip=1.1.1.1 dst_port=80 bytes_out=1 bytes_in=1 http_response=200 http_method=GET http_content_type=- http_user_agent=user_agent http_proxy_status_code=200 reason=- disposition=1 policy=policy role=1 duration=1 url=http://www.google.com/ab
#Apr 27 10:10:10 10.0.0.1 vendor=Websense product=Security product_version=1.1.1 action=permitted severity=1 category=1 user="ou=a ou=b" src_host=10.0.0.2 src_port=1025 dst_host=1.1.1.1 dst_ip=1.1.1.1 dst_port=80 bytes_out=1 bytes_in=1 http_response=200 http_method=GET http_content_type=- http_user_agent=user_agent http_proxy_status_code=200 reason=- disposition=1 policy=policy role=1 duration=1 url=http://1.1.1.1/ab
#Apr 27 10:10:10 10.0.0.1 vendor=Websense product=Security product_version=1.1.1 action=blocked severity=7 category=1 user="ou=a ou=b" src_host=10.0.0.3 src_port=1026 dst_host=live.com dst_ip=1.1.1.2 dst_port=443 bytes_out=2 bytes_in=6 http_response=200 http_method=CONNECT http_content_type=- http_user_agent=Mozilla/5.0_(compatible;_MSIE_9.0;_Windows_NT_6.1;_WOW64;_Trident/5.0) http_proxy_status_code=200 reason=- disposition=1 policy=policy2 role=1 duration=1 url=https://live.com
#Apr 27 10:10:10 10.0.0.1 vendor=Websense product=Security product_version=1.1.1 action=permitted severity=1 category=1 user="user" src_host=10.0.0.4 src_port=1027 dst_host=test.net dst_ip=1.1.1.3 dst_port=80 bytes_out=4 bytes_in=1 http_response=200 http_method=GET http_content_type=application/x-shockwave-flash http_user_agent=Mozilla/5.0_(compatible;_MSIE_9.0;_Windows_NT_6.1;_WOW64;_Trident/5.0) http_proxy_status_code=200 reason=- disposition=1 policy=policy role=1 duration=1 url=XXX://test.com/abc.html?def=ghi
#
# User-Agent without space
# url NOT normalized
# two http_reply_code
#
 #elsif ( $output_escape =~ /^(?:\<\d+\>)?([a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2})\s(\S+)\svendor=\S+ product=\S+ product_version=\S+ action=\S+ severity=\d+ category=\d+ user=\\\"([^\"]*?)\\\" src_host=(\S+) src_port=\d+ dst_host=(\S+) dst_ip=(\S+) dst_port=\d+ bytes_out=\d+ bytes_in=\d+ http_response=(\S+) http_method=(\S+) http_content_type=\S+ http_user_agent=(\S+) http_proxy_status_code=(\S+) reason=\S+ disposition=\d+ policy=\S+ role=\d+ duration=\d+ url=\w+\:\/\/[^\/]*?(\/\S*)?$/ ) {
 elsif ( $output_escape =~ /^(?:\<\d+\>)?([a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2})\s(\S+)\svendor=\S+ product=\S+ product_version=\S+ action=\S+ severity=\d+ category=\d+ user=(?:\\\")?(.*?)(?:\\\")? src_host=(\S+) src_port=\d+ dst_host=(\S+) dst_ip=(\S+) dst_port=\d+ bytes_out=\d+ bytes_in=\d+ http_response=(\S+) http_method=(\S+) http_content_type=\S+ http_user_agent=(\S+) http_proxy_status_code=(\S+) reason=\S+ disposition=\d+ policy=\S+ role=\d+ duration=\d+ url=.*?\:\/\/[^\/]*?(\/\S*)?$/ ) {
  $timestamp_central=$1; $server_hostname_ip=$2; $client_username=$3; $client_hostname_ip=$4; $client_http_host=$5; $server_remote_ip=$6; $http_reply_code=$7; $client_http_method=$8; $client_http_useragent=$9; $client_http_uri=$11;
  print "passage dans WebSense default regexp.\n" if $debug2;
  $client_http_useragent =~ s/\_/ /g;
  if( $http_reply_code eq "0" ){ $http_reply_code=$10 }
 }


 else {
  if( $syslogsock )
  {
   print $syslogsock "$host etplc: parser not exist with your logs !!! $output_escape\n";
  }
  else
  {
   print "parser not exist with your logs !!! $output_escape\n";
  }
 }

 
 print "timestamp_central: ",$timestamp_central if $timestamp_central && $debug2;
 print ", server_hostname_ip: ",$server_hostname_ip if $server_hostname_ip && $debug2;
 print ", timestamp_unix: ",$timestamp_unix if $timestamp_unix && $debug2;
 print ", client_hostname_ip: ",$client_hostname_ip if $client_hostname_ip && $debug2;
 print ", client_username: ",$client_username if $client_username && $debug2;
 print ", http_reply_code: ",$http_reply_code if $http_reply_code && $debug2;
 print ", client_http_method: ",$client_http_method if $client_http_method && $debug2;
 print ", client_http_uri: ",$client_http_uri if $client_http_uri && $debug2;
 print ", web_hostname_ip: ",$web_hostname_ip if $web_hostname_ip && $debug2;
 print ", client_http_useragent: ",$client_http_useragent if $client_http_useragent && $debug2;
 print ", client_http_referer: ",$client_http_referer if $client_http_referer && $debug2;
 print ", client_http_cookie: ",$client_http_cookie if $client_http_cookie && $debug2;
 print ", client_http_host: ",$client_http_host if $client_http_host && $debug2;
 print ", server_remote_ip: ",$server_remote_ip if $server_remote_ip && $debug2;
 print "\n" if $timestamp_central && $debug2;

####################################################################################################

 # de-encoded char :
 if( $client_http_uri )
 {
  my $countloop=0;
  #while( $client_http_uri =~ /\%/ )
  while( index($client_http_uri, '%') != -1 )
  {
   $countloop++;
   $client_http_uri=decodeURIComponent($client_http_uri);
   print "unescape: $client_http_uri\n" if $debug2;
   if( $countloop>4 ) { last }
  }
  $client_http_uri =~ s/\x00/\%00/g;
  $client_http_uri =~ s/\x0d/\%0D/g;
  $client_http_uri =~ s/\x0a/\%0A/g;
 }

####################################################################################################


 if( $client_http_host || $client_http_uri )
 {
  my $etmsg;

  foreach $etmsg ( sort( keys %hash ) )
  {
   my $jump=0;
   my $founduricourt1=0;
   my $foundurilong1=0;
   my $foundurilen=0;
   my $foundurilongdistance1=0;
   my $foundagent=0;
   my $foundmethod=0;
   my $foundreferer=0;
   my $foundcookie=0;
   my $foundpcrereferer=0;
   my $foundpcreuri=0;
   my $foundpcreagent=0;
   my $foundpcrecookie=0;
   my $foundremoteip=0;
   my $foundhost=0;
   my $foundpcrehost=0;

   foreach $clef ( sort( keys %{$hash{$etmsg}} ) )
   {
    print "hash2 etmsg: $etmsg, clef: $clef\n" if $debug2 && $_;

    if( $clef eq "httpmethod" && !$jump )
    {
     if( $hash{$etmsg}{"httpmethod"}[1] eq "nocase" && $client_http_method && index(lc($client_http_method), lc($hash{$etmsg}{"httpmethod"}[0])) != -1 )
     {
      print "ici1a: ",$hash{$etmsg}{"httpmethod"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpmethod"}[0];
      $foundmethod=1;
     }
     elsif( $hash{$etmsg}{"httpmethod"}[0] && $client_http_method && index($client_http_method, $hash{$etmsg}{"httpmethod"}[0]) != -1 )
     {
      print "ici1b: ",$hash{$etmsg}{"httpmethod"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpmethod"}[0];
      $foundmethod=1;
     }
     elsif( $hash{$etmsg}{"httpmethod"}[0] )
     {
      print "method not found: jump (",$hash{$etmsg}{"httpmethod"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "httpuricourt" && !$jump )
    {
     if( $hash{$etmsg}{"httpuricourt"}[0] && $hash{$etmsg}{"httpuricourt"}[1] && $hash{$etmsg}{"httpuricourt"}[2] && $client_http_uri && index(lc($client_http_uri), $hash{$etmsg}{"httpuricourt"}[0]) == $hash{$etmsg}{"httpuricourt"}[2] )
     {
      print "ici2a: ",$hash{$etmsg}{"httpuricourt"}[0],", depth:",$hash{$etmsg}{"httpuricourt"}[1],", offset:",$hash{$etmsg}{"httpuricourt"}[2],"\n" if $debug2 && $hash{$etmsg}{"httpuricourt"}[0] && $hash{$etmsg}{"httpuricourt"}[1] && $hash{$etmsg}{"httpuricourt"}[2];
      $founduricourt1=1;
     }
     elsif( $hash{$etmsg}{"httpuricourt"}[0] && $hash{$etmsg}{"httpuricourt"}[1] && !$hash{$etmsg}{"httpuricourt"}[2] && $client_http_uri && index(lc($client_http_uri), $hash{$etmsg}{"httpuricourt"}[0]) == 0 )
     {
      print "ici2b: ",$hash{$etmsg}{"httpuricourt"}[0],", depth:",$hash{$etmsg}{"httpuricourt"}[1],"\n" if $debug2 && $hash{$etmsg}{"httpuricourt"}[0] && $hash{$etmsg}{"httpuricourt"}[1];
      $founduricourt1=1;
     }
     elsif( $hash{$etmsg}{"httpuricourt"}[0] && !$hash{$etmsg}{"httpuricourt"}[1] && $client_http_uri && index(lc($client_http_uri), $hash{$etmsg}{"httpuricourt"}[0]) != -1 )
     {
      print "ici2c: ",$hash{$etmsg}{"httpuricourt"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpuricourt"}[0];
      $founduricourt1=1;
     }
     elsif( $hash{$etmsg}{"httpuricourt"}[0] )
     {
      print "uri not found2: jump (",$hash{$etmsg}{"httpuricourt"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "httpurilen" && !$jump )
    {
     if( $hash{$etmsg}{"httpurilen"}[0] && $client_http_uri && $hash{$etmsg}{"httpurilen"}[0]=~/^(\d+)$/ && length($client_http_uri) == $1 )	# urilen:80;
     {
      print "ici15a: ",$hash{$etmsg}{"httpurilen"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpurilen"}[0];
      $foundurilen=1;
     }
     elsif( $hash{$etmsg}{"httpurilen"}[0] && $client_http_uri && $hash{$etmsg}{"httpurilen"}[0]=~/^\>(\d+)$/ && length($client_http_uri) > $1 )	# urilen:>80;
     {
      print "ici15b: ",$hash{$etmsg}{"httpurilen"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpurilen"}[0];
      $foundurilen=1;
     }
     elsif( $hash{$etmsg}{"httpurilen"}[0] && $client_http_uri && $hash{$etmsg}{"httpurilen"}[0]=~/^\<(\d+)$/ && length($client_http_uri) < $1 )        # urilen:<80;
     {
      print "ici15c: ",$hash{$etmsg}{"httpurilen"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpurilen"}[0];
      $foundurilen=1;
     }
     elsif( $hash{$etmsg}{"httpurilen"}[0] && $client_http_uri && $hash{$etmsg}{"httpurilen"}[0]=~/^(\d+)\<\>(\d+)$/ && length($client_http_uri) > $1 && length($client_http_uri) < $2 )        # urilen:25<>45;
     {
      print "ici15d: ",$hash{$etmsg}{"httpurilen"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpurilen"}[0];
      $foundurilen=1;
     }
     elsif( $hash{$etmsg}{"httpurilen"}[0] )
     {
      print "urilen not found15: jump (",$hash{$etmsg}{"httpurilen"}[0]," and ",length($client_http_uri),")\n" if $debug2 && $client_http_uri;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "httpurilong" && !$jump )
    {
     my $hashindexhttpurilong=0;
     foreach ( @{$hash{$etmsg}{"httpurilong"}} )
     {
      if( $hash{$etmsg}{"httpurilong"}[$hashindexhttpurilong] && $client_http_uri && index(lc($client_http_uri), lc($hash{$etmsg}{"httpurilong"}[$hashindexhttpurilong])) != -1 )
      {
       print "ici3: ",$hash{$etmsg}{"httpurilong"}[$hashindexhttpurilong],"\n" if $debug2 && $hash{$etmsg}{"httpurilong"}[$hashindexhttpurilong];
       $foundurilong1=1;
      }
      elsif( $hash{$etmsg}{"httpurilong"}[$hashindexhttpurilong] )
      {
       print "uri not found: jump (",$hash{$etmsg}{"httpurilong"}[$hashindexhttpurilong],")\n" if $debug2;
       $jump=1;
       $foundurilong1=0;
       last;
      }
      $hashindexhttpurilong++;
     }
    }

    elsif( $clef eq "httpurilongdistance" && !$jump )
    {
     my $hashindexhttpurilongdistance=0;
     my @result;
     foreach ( @{$hash{$etmsg}{"httpurilongdistance"}} )
     {
      if( $hash{$etmsg}{"httpurilongdistance"}[$hashindexhttpurilongdistance] && $client_http_uri )
      {
       $result[$hashindexhttpurilongdistance] = index(lc($client_http_uri), lc($hash{$etmsg}{"httpurilongdistance"}[$hashindexhttpurilongdistance]));
       if( $result[$hashindexhttpurilongdistance] != -1 )
       {
        if( $hashindexhttpurilongdistance == 0 )
        {
         print "ici9".$hashindexhttpurilongdistance.": ".$result[$hashindexhttpurilongdistance]." (".$hash{$etmsg}{"httpurilongdistance"}[$hashindexhttpurilongdistance].")\n" if $debug2;
        }
        else
        {
         if( $result[$hashindexhttpurilongdistance] > $result[($hashindexhttpurilongdistance-1)] )
         {
          print "ici9".$hashindexhttpurilongdistance.": ".$result[$hashindexhttpurilongdistance]." (".$hash{$etmsg}{"httpurilongdistance"}[$hashindexhttpurilongdistance].")\n" if $debug2;
          $foundurilongdistance1=1;
         }
         else
         {
          print "uri distance not found1: jump (",$hash{$etmsg}{"httpurilongdistance"}[$hashindexhttpurilongdistance],")\n" if $debug2;
          $jump=1;
          $foundurilongdistance1=0;
          last;
         }
        }
       }
       else
       {
        print "uri distance not found2: jump (",$hash{$etmsg}{"httpurilongdistance"}[$hashindexhttpurilongdistance],")\n" if $debug2;
        $jump=1;
        $foundurilongdistance1=0;
        last;
       }
      }
      $hashindexhttpurilongdistance++;
     }
    }

    elsif( $clef eq "httpagentshort" && !$jump )
    {
     # equal:
     if( $hash{$etmsg}{"httpagentshort"}[0] && !$hash{$etmsg}{"httpagentshort"}[1] && $hash{$etmsg}{"httpagentshort"}[2] && $client_http_useragent && (lc($client_http_useragent) eq (lc($hash{$etmsg}{"httpagentshort"}[0]))) )
     {
      print "fp_ici4a: ",$hash{$etmsg}{"httpagentshort"}[0],", , ",$hash{$etmsg}{"httpagentshort"}[2],"\n" if $debug2 && $hash{$etmsg}{"httpagentshort"}[0] && $hash{$etmsg}{"httpagentshort"}[2];
      $foundagent=1;
     }
     # depth:
     elsif( $hash{$etmsg}{"httpagentshort"}[0] && $hash{$etmsg}{"httpagentshort"}[1] && !$hash{$etmsg}{"httpagentshort"}[2] && $client_http_useragent && index(lc($client_http_useragent), $hash{$etmsg}{"httpagentshort"}[0]) == 0 )
     {
      print "fp_ici4b: ",$hash{$etmsg}{"httpagentshort"}[0],", ",$hash{$etmsg}{"httpagentshort"}[1],"\n" if $debug2 && $hash{$etmsg}{"httpagentshort"}[0] && $hash{$etmsg}{"httpagentshort"}[1];
      $foundagent=1;
     }
     elsif( $hash{$etmsg}{"httpagentshort"}[0] && !$hash{$etmsg}{"httpagentshort"}[1] && !$hash{$etmsg}{"httpagentshort"}[2] && $client_http_useragent && index(lc($client_http_useragent), $hash{$etmsg}{"httpagentshort"}[0]) != -1 )
     {
      print "fp_ici4c: ",$hash{$etmsg}{"httpagentshort"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpagentshort"}[0];
      $foundagent=1;
     }
     elsif( $hash{$etmsg}{"httpagentshort"}[0] )
     {
      print "fp_agent not found: jump (",$hash{$etmsg}{"httpagentshort"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "httpreferer" && !$jump )
    {
     if( $hash{$etmsg}{"httpreferer"}[0] && $client_http_referer && index(lc($client_http_referer), $hash{$etmsg}{"httpreferer"}[0]) != -1 )
     {
      print "ici10: ",$hash{$etmsg}{"httpreferer"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpreferer"}[0];
      $foundreferer=1;
     }
     elsif( $hash{$etmsg}{"httpreferer"}[0] )
     {
      print "httpreferer not found: jump (",$hash{$etmsg}{"httpreferer"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "httphost" && !$jump )
    {
     if( $hash{$etmsg}{"httphost"}[0] && $client_http_host && index(lc($client_http_host), $hash{$etmsg}{"httphost"}[0]) != -1 )
     {
      print "ici13: ",$hash{$etmsg}{"httphost"}[0],"\n" if $debug2 && $hash{$etmsg}{"httphost"}[0];
      $foundhost=1;
     }
     elsif( $hash{$etmsg}{"httphost"}[0] )
     {
      print "httphost not found: jump (",$hash{$etmsg}{"httphost"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "httpcookie" && !$jump )
    {
     if( $hash{$etmsg}{"httpcookie"}[1] && $client_http_cookie && index(lc($client_http_cookie), lc($hash{$etmsg}{"httpcookie"}[0])) != -1 )
     {
      print "ici11a: ",$hash{$etmsg}{"httpcookie"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpcookie"}[0];
      $foundcookie=1;
     }
     elsif( !$hash{$etmsg}{"httpcookie"}[1] && $client_http_cookie && index($client_http_cookie, $hash{$etmsg}{"httpcookie"}[0]) != -1 )
     {
      print "ici11b: ",$hash{$etmsg}{"httpcookie"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpcookie"}[0];
      $foundcookie=1;
     }
     elsif( $hash{$etmsg}{"httpcookie"}[0] )
     {
      print "httpcookie not found: jump (",$hash{$etmsg}{"httpcookie"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "pcrereferer" && !$jump )
    {
     if( $hash{$etmsg}{"pcrereferer"}[0] && $client_http_referer && ($hash{$etmsg}{"pcrereferer"}[0] eq '^\-$') && $client_http_referer eq '-' )
     {
      print "ici5b: ",$hash{$etmsg}{"pcrereferer"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcrereferer"}[0];
      $foundpcrereferer=1;
     }
     elsif( $hash{$etmsg}{"pcrereferer"}[0] && $client_http_referer and not ($hash{$etmsg}{"pcrereferer"}[0] eq '^\-$') && $client_http_referer =~ /$hash{$etmsg}{"pcrereferer"}[0]/i )
     {
      print "ici5a: ",$hash{$etmsg}{"pcrereferer"}[0]," \n" if $debug2 && $hash{$etmsg}{"pcrereferer"}[0];
      $foundpcrereferer=1;
     }
     elsif( $hash{$etmsg}{"pcrereferer"}[0] )
     {
      print "pcrereferer not found: jump (",$hash{$etmsg}{"pcrereferer"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "pcrehost" && !$jump )
    {
     if( $hash{$etmsg}{"pcrehost"}[0] && $client_http_host && ($hash{$etmsg}{"pcrehost"}[0] eq '^\-$') && $client_http_host eq '-' )
     {
      print "ici14a: ",$hash{$etmsg}{"pcrehost"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcrehost"}[0];
      $foundpcrehost=1;
     }
     elsif( $hash{$etmsg}{"pcrehost"}[0] && $client_http_host and not ($hash{$etmsg}{"pcrehost"}[0] eq '^\-$') && $client_http_host =~ /$hash{$etmsg}{"pcrehost"}[0]/i )
     {
      print "ici14b: ",$hash{$etmsg}{"pcrehost"}[0]," \n" if $debug2 && $hash{$etmsg}{"pcrehost"}[0];
      $foundpcrehost=1;
     }
     elsif( $hash{$etmsg}{"pcrehost"}[0] )
     {
      print "pcrehost not found: jump (",$hash{$etmsg}{"pcrehost"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "pcreagent" && !$jump )
    {
     if( $hash{$etmsg}{"pcreagent"}[0] && $client_http_useragent && ($hash{$etmsg}{"pcreagent"}[0] eq '^\-$') && $client_http_useragent eq '-' )
     {
      print "ici6c: ",$hash{$etmsg}{"pcreagent"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcreagent"}[0];
      $foundpcreagent=1;
     }
     elsif( $hash{$etmsg}{"pcreagent"}[1] && $client_http_useragent and not ($hash{$etmsg}{"pcreagent"}[0] eq '^\-$') && $client_http_useragent =~ /$hash{$etmsg}{"pcreagent"}[0]/i )
     {
      print "ici6a: ",$hash{$etmsg}{"pcreagent"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcreagent"}[0];
      $foundpcreagent=1;
     }
     elsif( !$hash{$etmsg}{"pcreagent"}[1] && $client_http_useragent and not ($hash{$etmsg}{"pcreagent"}[0] eq '^\-$') && $client_http_useragent =~ /$hash{$etmsg}{"pcreagent"}[0]/ )
     {
      print "ici6b: ",$hash{$etmsg}{"pcreagent"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcreagent"}[0];
      $foundpcreagent=1;
     }
     elsif( $hash{$etmsg}{"pcreagent"}[0] )
     {
      print "pcreagent not found: jump (",$hash{$etmsg}{"pcreagent"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "pcrecookie" && !$jump )
    {
     if( $hash{$etmsg}{"pcrecookie"}[1] && $client_http_cookie && $client_http_cookie =~ /$hash{$etmsg}{"pcrecookie"}[0]/i )
     {
      print "ici7a: ",$hash{$etmsg}{"pcrecookie"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcrecookie"}[0];
      $foundpcrecookie=1;
     }
     elsif( !$hash{$etmsg}{"pcrecookie"}[1] && $client_http_cookie && $client_http_cookie =~ /$hash{$etmsg}{"pcrecookie"}[0]/ )
     {
      print "ici7b: ",$hash{$etmsg}{"pcrecookie"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcrecookie"}[0];
      $foundpcrecookie=1;
     }
     elsif( $hash{$etmsg}{"pcrecookie"}[0] )
     {
      print "pcrecookie not found: jump (",$hash{$etmsg}{"pcrecookie"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "pcreuri" && !$jump )
    {
     if( $hash{$etmsg}{"pcreuri"}[1] && $client_http_uri && $client_http_uri =~ /$hash{$etmsg}{"pcreuri"}[0]/i )
     {
      print "ici8a: ",$hash{$etmsg}{"pcreuri"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcreuri"}[0];
      $foundpcreuri=1;
     }
     elsif( !$hash{$etmsg}{"pcreuri"}[1] && $client_http_uri && $client_http_uri =~ /$hash{$etmsg}{"pcreuri"}[0]/ )
     {
      print "ici8b: ",$hash{$etmsg}{"pcreuri"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcreuri"}[0];
      $foundpcreuri=1;
     }
     elsif( $hash{$etmsg}{"pcreuri"}[0] )
     {
      print "pcreuri not found: jump (",$hash{$etmsg}{"pcreuri"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }
    
    elsif( $clef eq "remoteip" && !$jump )
    {
     if( $hash{$etmsg}{"remoteip"}[0] && $server_remote_ip && $hash{$etmsg}{"remoteip"}[0] eq $server_remote_ip )
     {
      print "ici12a: ",$hash{$etmsg}{"remoteip"}[0],"\n" if $debug2 && $hash{$etmsg}{"remoteip"}[0];
      $foundremoteip=1;
     }
     elsif( $hash{$etmsg}{"remoteip"}[0] )
     {
      print "remoteip not found: jump (",$hash{$etmsg}{"remoteip"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }
   }
   unless( $jump )
   {
    if( $syslogsock && ($foundmethod or $founduricourt1 or $foundurilong1 or $foundurilen or $foundurilongdistance1 or $foundagent or $foundreferer or $foundcookie or $foundpcrereferer or $foundpcreagent or $foundpcrecookie or $foundpcreuri or $foundremoteip or $foundhost or $foundpcrehost) )
    {
     lock($queue);
     my $sendtosyslog;
     my $tutu='';
     #print $syslogsock "$host etplc: ok trouvé: ";
     $sendtosyslog .= "$host etplc: ok trouvé: ";

     #print $syslogsock "timestamp: $timestamp_central, " if $timestamp_central;
     $sendtosyslog .= "timestamp: $timestamp_central, " if $timestamp_central;

     #print $syslogsock "server_hostname_ip: $server_hostname_ip, " if $server_hostname_ip;
     $sendtosyslog .= "server_hostname_ip: $server_hostname_ip, " if $server_hostname_ip;

     #print $syslogsock "client_hostname_ip: $client_hostname_ip, " if $client_hostname_ip;
     $sendtosyslog .= "client_hostname_ip: $client_hostname_ip, " if $client_hostname_ip;

     #print $syslogsock "client_username: $client_username, " if $client_username;
     $sendtosyslog .= "client_username: $client_username, " if $client_username;

     #print $syslogsock "client_http_method: $client_http_method, " if $client_http_method;
     $sendtosyslog .= "client_http_method: $client_http_method, " if $client_http_method;

     #print $syslogsock "client_http_uri: $client_http_uri, " if $client_http_uri;
     $sendtosyslog .= "client_http_uri: $client_http_uri, " if $client_http_uri;

     #print $syslogsock "client_http_useragent: $client_http_useragent, " if $client_http_useragent;
     $sendtosyslog .= "client_http_useragent: $client_http_useragent, " if $client_http_useragent;

     #print $syslogsock "client_http_referer: $client_http_referer, " if $client_http_referer;
     $sendtosyslog .= "client_http_referer: $client_http_referer, " if $client_http_referer;

     #print $syslogsock "client_http_cookie: $client_http_cookie, " if $client_http_cookie;
     $sendtosyslog .= "client_http_cookie: $client_http_cookie, " if $client_http_cookie;

     #print $syslogsock "client_http_host: $client_http_host, " if $client_http_host;
     $sendtosyslog .= "client_http_host: $client_http_host, " if $client_http_host;

     #print $syslogsock "http_reply_code: $http_reply_code, " if $http_reply_code;
     $sendtosyslog .= "http_reply_code: $http_reply_code, " if $http_reply_code;

     #print $syslogsock "server_remote_ip: $server_remote_ip, " if $server_remote_ip;
     $sendtosyslog .= "server_remote_ip: $server_remote_ip, " if $server_remote_ip;

     #print $syslogsock "etmsg: $etmsg" if $etmsg;
     $sendtosyslog .= "etmsg: $etmsg" if $etmsg;

     #print $syslogsock ", etmethod: ",$hash{$etmsg}{"httpmethod"}[0] if $foundmethod;
     $tutu=$hash{$etmsg}{"httpmethod"}[0];
     #print $syslogsock ", etmethod: $tutu" if $foundmethod;
     $sendtosyslog .= ", etmethod: $tutu" if $foundmethod;

     #print $syslogsock ", eturishort: ",$hash{$etmsg}{"httpuricourt"}[0] if $founduricourt1;
     $tutu=$hash{$etmsg}{"httpuricourt"}[0];
     $tutu .= " depth:".$hash{$etmsg}{"httpuricourt"}[1] if $hash{$etmsg}{"httpuricourt"}[1];
     $tutu .= " offset:".$hash{$etmsg}{"httpuricourt"}[2] if $hash{$etmsg}{"httpuricourt"}[2];
     #print $syslogsock ", eturishort: $tutu" if $founduricourt1;
     $sendtosyslog .= ", eturishort: $tutu" if $founduricourt1;

     #print $syslogsock ", eturilong: ",$hash{$etmsg}{"httpurilong"}[0] if $foundurilong1;
     $tutu=$hash{$etmsg}{"httpurilong"}[0];
     #print $syslogsock ", eturilong: $tutu" if $foundurilong1;
     $sendtosyslog .= ", eturilong: $tutu" if $foundurilong1;

     #if( $foundurilongdistance1 ){ print $syslogsock ", eturilongdistance: "; print $syslogsock "$_ ",foreach values $hash{$etmsg}{"httpurilongdistance"} }
     #if( $foundurilongdistance1 ){ print $syslogsock ", eturilongdistance: "; $tutu.= "$_ ",foreach values $hash{$etmsg}{"httpurilongdistance"}; print $syslogsock $tutu; }
     if( $foundurilongdistance1 ){ $sendtosyslog .= ", eturilongdistance: "; $tutu.= "$_ ",foreach values $hash{$etmsg}{"httpurilongdistance"}; $sendtosyslog .= $tutu; }

     #print $syslogsock ", etagent: ",$hash{$etmsg}{"httpagentshort"}[0] if $foundagent;
     $tutu=$hash{$etmsg}{"httpagentshort"}[0];
     #print $syslogsock ", etagent: $tutu" if $foundagent;
     $sendtosyslog .= ", etagent: $tutu" if $foundagent;

     #print $syslogsock ", etreferer: ",$hash{$etmsg}{"httpreferer"}[0] if $foundreferer;
     $tutu=$hash{$etmsg}{"httpreferer"}[0];
     #print $syslogsock ", etreferer: $tutu" if $foundreferer;
     $sendtosyslog .= ", etreferer: $tutu" if $foundreferer;

     #print $syslogsock ", etcookie: ",$hash{$etmsg}{"httpcookie"}[0] if $foundcookie;
     $tutu=$hash{$etmsg}{"httpcookie"}[0];
     #print $syslogsock ", etcookie: $tutu" if $foundcookie;
     $sendtosyslog .= ", etcookie: $tutu" if $foundcookie;

     #print $syslogsock ", etpcrereferer: ",$hash{$etmsg}{"pcrereferer"}[0] if $foundpcrereferer;
     $tutu=$hash{$etmsg}{"pcrereferer"}[0];
     #print $syslogsock ", etpcrereferer: $tutu" if $foundpcrereferer;
     $sendtosyslog .= ", etpcrereferer: $tutu" if $foundpcrereferer;

     #print $syslogsock ", etpcreagent: ",$hash{$etmsg}{"pcreagent"}[0] if $foundpcreagent;
     $tutu=$hash{$etmsg}{"pcreagent"}[0];
     #print $syslogsock ", etpcreagent: $tutu" if $foundpcreagent;
     $sendtosyslog .= ", etpcreagent: $tutu" if $foundpcreagent;

     #print $syslogsock ", etpcrecookie: ",$hash{$etmsg}{"pcrecookie"}[0] if $foundpcrecookie;
     $tutu=$hash{$etmsg}{"pcrecookie"}[0];
     #print $syslogsock ", etpcrecookie: $tutu" if $foundpcrecookie;
     $sendtosyslog .= ", etpcrecookie: $tutu" if $foundpcrecookie;

     #print $syslogsock ", etpcreuri: ",$hash{$etmsg}{"pcreuri"}[0] if $foundpcreuri;
     $tutu=$hash{$etmsg}{"pcreuri"}[0];
     #print $syslogsock ", etpcreuri: $tutu" if $foundpcreuri;
     $sendtosyslog .= ", etpcreuri: $tutu" if $foundpcreuri;

     #print $syslogsock ", etremoteip: ",$hash{$etmsg}{"remoteip"}[0] if $foundremoteip;
     $tutu=$hash{$etmsg}{"remoteip"}[0];
     #print $syslogsock ", etremoteip: $tutu" if $foundremoteip;
     $sendtosyslog .= ", etremoteip: $tutu" if $foundremoteip;

     #print $syslogsock ", ethost: ",$hash{$etmsg}{"httphost"}[0] if $foundhost;
     $tutu=$hash{$etmsg}{"httphost"}[0];
     #print $syslogsock ", ethost: $tutu" if $foundhost;
     $sendtosyslog .= ", ethost: $tutu" if $foundhost;

     #print $syslogsock ", eturilen: ",$hash{$etmsg}{"httpurilen"}[0] if $foundurilen;
     $tutu=$hash{$etmsg}{"httpurilen"}[0];
     $sendtosyslog .= ", eturilen: $tutu" if $foundurilen;

     #print $syslogsock ", etpcrehost: ",$hash{$etmsg}{"pcrehost"}[0] if $foundpcrehost;
     $tutu=$hash{$etmsg}{"pcrehost"}[0];
     #print $syslogsock ", etpcrehost: $tutu" if $foundpcrehost;
     $sendtosyslog .= ", etpcrehost: $tutu" if $foundpcrehost;

     print $syslogsock $sendtosyslog if $syslogsock;
     #print $syslogsock "\n";
    }
    elsif( $foundmethod or $founduricourt1 or $foundurilong1 or $foundurilen or $foundurilongdistance1 or $foundagent or $foundreferer or $foundcookie or $foundpcrereferer or $foundpcreagent or $foundpcrecookie or $foundpcreuri or $foundremoteip or $foundhost or $foundpcrehost)
    {
     lock($queue);
     print color("red"), "ok trouvé: ", color("reset");
     print color("blue"), "timestamp: $timestamp_central, " if $timestamp_central;
     print "server_hostname_ip: $server_hostname_ip, " if $server_hostname_ip;
     print "client_hostname_ip: $client_hostname_ip, " if $client_hostname_ip;
     print "client_username: $client_username, " if $client_username;
     print "client_http_method: $client_http_method, " if $client_http_method;
     print "client_http_uri: $client_http_uri, " if $client_http_uri;
     print "client_http_useragent: $client_http_useragent, " if $client_http_useragent;
     print "client_http_referer: $client_http_referer, " if $client_http_referer;
     print "client_http_cookie: $client_http_cookie, " if $client_http_cookie;
     print "client_http_host: $client_http_host, " if $client_http_host;
     print color("reset"), "http_reply_code: $http_reply_code, ", color("blue") if $http_reply_code;
     print "server_remote_ip: $server_remote_ip, " if $server_remote_ip;
     print color("reset"), color("green"), "etmsg: $etmsg" if $etmsg;
     print ", etmethod: ",$hash{$etmsg}{"httpmethod"}[0] if $foundmethod;
     print ", eturishort: ",$hash{$etmsg}{"httpuricourt"}[0] if $founduricourt1; print " depth:",$hash{$etmsg}{"httpuricourt"}[1] if $founduricourt1 && $hash{$etmsg}{"httpuricourt"}[1]; print " offset:",$hash{$etmsg}{"httpuricourt"}[2] if $founduricourt1 && $hash{$etmsg}{"httpuricourt"}[2];
     print ", eturilong: ",$hash{$etmsg}{"httpurilong"}[0] if $foundurilong1;
     if( $foundurilongdistance1 ){ print ", eturilongdistance: "; print "$_ ",foreach values $hash{$etmsg}{"httpurilongdistance"} }
     print ", etagent: ",$hash{$etmsg}{"httpagentshort"}[0] if $foundagent;
     print ", etreferer: ",$hash{$etmsg}{"httpreferer"}[0] if $foundreferer;
     print ", etcookie: ",$hash{$etmsg}{"httpcookie"}[0] if $foundcookie;
     print ", etpcrereferer: ",$hash{$etmsg}{"pcrereferer"}[0] if $foundpcrereferer;
     print ", etpcreagent: ",$hash{$etmsg}{"pcreagent"}[0] if $foundpcreagent;
     print ", etpcrecookie: ",$hash{$etmsg}{"pcrecookie"}[0] if $foundpcrecookie;
     print ", etpcreuri: ",$hash{$etmsg}{"pcreuri"}[0] if $foundpcreuri;
     print ", etremoteip: ",$hash{$etmsg}{"remoteip"}[0] if $foundremoteip;
     print ", ethost: ",$hash{$etmsg}{"httphost"}[0] if $foundhost;
     print ", etpcrehost: ",$hash{$etmsg}{"pcrehost"}[0] if $foundpcrehost;
     print ", eturilen: ",$hash{$etmsg}{"httpurilen"}[0] if $foundurilen;
     print color("reset"), "\n";
    }
   }
  }
 }

 $timestamp_central=0; $server_hostname_ip=0; $timestamp_unix=0; $client_hostname_ip=0; $client_username=0; $http_reply_code=0; $client_http_method=0; $client_http_uri=0; $web_hostname_ip=0; $client_http_useragent=0; $client_http_referer=0; $client_http_cookie=0; $server_remote_ip=0; $client_http_host=0;

  }
 }
), 1..$max_procs;

# Send work to the thread
$queue->enqueue($_) while( <STDIN> );

$queue->enqueue( (undef) x $max_procs );

# terminate.
$_->join() for @threads;

exit(0);

