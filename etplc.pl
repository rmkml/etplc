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

####################################################################################################

my $recieved_data;

my ($timestamp_central,$server_hostname_ip,$timestamp_unix,$client_hostname_ip,$client_username,$http_reply_code,$client_http_method,$client_http_uri,$web_hostname_ip,$client_http_useragent,$client_http_referer,$client_http_cookie,$server_remote_ip,$client_http_host,);

my $output_escape;
my @tableauuricontent;
my @tableauuseragent;
my @tableauhttpmethod;
my $max_procs=0;
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
GetOptions ("f=s"      => \$file,    # string
            "d"        => \$debug,   # flag
            "s"        => \$syslog,  # flag
            "c=s"      => \$category)# string
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

####################################################################################################

if( open(CPUINFO, "/proc/cpuinfo") )
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

 my $urilen1='\s*urilen\:\s*\d*\s*\<?\s*\>?\s*\d+\;';
 my $flowbits1='\s*flowbits\:.*?\;';
 my $flow1='flow\:\s*(?:to_server|to_client|from_client|from_server)?(?:\s*\,)?(?:established)?(?:\s*\,\s*)?(?:to_server|to_client|from_client|from_server)?\;';
 my $httpmethod='\s*content\:\"([gG][eE][tT]|[pP][oO][sS][tT]|[hH][eE][aA][dD]|[sS][eE][aA][rR][cC][hH]|[pP][rR][oO][pP][fF][iI][nN][dD]|[tT][rR][aA][cC][eE]|[oO][pP][tT][iI][oO][nN][sS]|[dD][eE][bB][uU][gG]|[cC][oO][nN][nN][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[pP][uU][tT])\s*[^\"]*?\"\;(?:\s*(nocase)\;\s*|\s*http_method\;\s*|\s*depth\:\d+\;\s*)*';
 my $contentoptions1='\s*(fast_pattern)(?:\:only|\:\d+\,\d+)?\;|\s*(nocase)\;|\s*offset\:\d+\;|\s*depth\:\d+\;|\s*distance\:\s*\-?(\d+)\;|\s*within\:(\d+)\;|\s*http_raw_uri\;';
 my $negateuricontent1='\s*(?:uri)?content\:\!\"[^\"]*?\"\s*\;(?:\s*fast_pattern(?:\:only|\d+\,\d+)?\;|\s*nocase\;|\s*http_uri\;|\s*http_header\;|\s*http_cookie\;|\s*offset\:\d+\;|\s*depth\:\d+\;|\s*http_raw_uri\;|\s*distance\:\s*\-?\d+\;|\s*within\:\d+\;|\s*http_client_body\;)*';
 my $extracontentoptions='\s*threshold\:.*?\;|\s*flowbits\:.*?\;|\s*isdataat\:\d+(?:\,relative)?\;|\s*dsize\:[\<\>]*\d+\;|\s*urilen\:\s*\d*\s*\<?\s*\>?\s*\d+\;|\s*detection_filter\:.*?\;|\s*priority\:\d+\;|\s*metadata\:.*?\;';
 my $referencesidrev='(?:\s*reference\:.*?\;\s*)*\s*classtype\:.*?\;\s*sid\:\d+\;\s*rev\:\d+\;\s*\)\s*';
 my $pcreuri='\s*pcre\:\"\/(.*?)\/[smiUGDIR]*\"\;'; # not header/Cookie/Post_payload!
 my $pcreagent='\s*pcre\:\"\/(.*?)\/[smiH]*\"\;';
 my $pcrecookie='\s*pcre\:\"\/(.*?)\/[smiC]*\"\;';

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
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$flowbits1)?(?:$urilen1)?(?:$httpmethod)?(?:$urilen1)?(?:$negateuricontent1)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*(?:http_uri|http_raw_uri)\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreuri)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreagent)?(?:$negateuricontent1)?(?:$extracontentoptions)?$referencesidrev$/ )
 {
  my $etmsg1=$1;
  my $http_method2=0;
  my $http_methodnocase3=0;
  print "brut1: $_\n" if $debug1;
  #print "here1: 1: $1, 2: $2, 3: $3, 4: $4, 5: $5, 6: $6, 7: $7, 8: $8, 9: $9, 10: $10, 11: $11, 12: $12, 13: $13, 14: $14, 15: $15, 16: $16, 17: $17, 18: $18, 19: $19, 20: $20, 21: $21, 22: $22, 23: $23, 24: $24, 25: $25, 26: $26, 27: $27, 28: $28, 29: $29, 30: $30, 31: $31, 32: $32, 33: $33, 34: $34, 35: $35, 36: $36, 37: $37, $38, $39, 40: $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, 50: $50, $51, $52, $53, 54: $54, $55, $56, $57, $58, $59, 60: $60, $61, $62, $63, $64, $65, $66, $67, $68, $69, 70: $70, $71, $72, $73, $74, $75, $76, $77, $78, $79, 80: $80, $81, $82, $83, $84, $85, $86, $87, $88, $89, 90: $90, $91, $92, $93, $94, 95: $95, $96, $97, $98, $99, 100: $100, $101, $102, 103: $103, $104, $105, $106, $107, $108, $109, 110: $110, $111, $112, $113, $114, $115, $116, $117, $118, $119, 120: $120, 121: $121, $122, $123, $124, $125, $126, $127, $128, $129, 130: $130, $131, $132, $133, $134, $135, $136, $137, $138, $139, 140: $140\n" if $debug1;

     $http_method2=$2 if $2;
     $http_methodnocase3=$3 if $3;
  my $http_uri03=$4 if $4;
  my $http_urifast5=$5 if $5;
  my $http_urinocase5=$6 if $6;		# 5
  my $http_urifast9=$9 if $9;
  my $http_urinocase10=$10 if $10;
  my $http_uri08=$13 if $13;		# 11
  my $http_urifast14=$14 if $14;
  my $http_urinocase12=$15 if $15;	# 12
  my $distance9=$16 if defined($16);	# 13
  my $distance10=$17 if defined($17);	# 14
  my $http_urifast18=$18 if $18;
  my $http_urinocase15=$19 if $19;	# 15
  my $distance11=$20 if defined($20);	# 16
  my $distance12=$21 if defined($21);	# 17
  my $http_uri13=$22 if $22;		# 18
  my $http_urifast23=$23 if $23;
  my $http_urinocase19=$24 if $24;	# 19
  my $distance14=$25 if defined($25);	# 20
  my $distance15=$26 if defined($26);	# 21
  my $http_urifast27=$27 if $27;
  my $http_urinocase22=$28 if $28;	# 22
  my $distance16=$29 if defined($29);	# 23
  my $distance17=$30 if defined($30);	# 24
  my $http_uri18=$31 if $31;		# 25
  my $http_urifast32=$32 if $32;
  my $http_urinocase26=$33 if $33;	# 26
  my $distance19=$34 if defined($34);	# 27
  my $distance20=$35 if defined($35);	# 28
  my $http_urifast36=$36 if $36;
  my $http_urinocase29=$37 if $37;	# 29
  my $distance21=$38 if defined($38);	# 30
  my $distance22=$39 if defined($39);	# 31
  my $http_uri23=$40 if $40;		# 32
  my $http_urifast41=$41 if $41;
  my $http_urinocase33=$42 if $42;	# 33
  my $distance24=$43 if defined($43);	# 34
  my $distance25=$44 if defined($44);	# 35
  my $http_urifast44=$45 if $45;
  my $http_urinocase36=$46 if $46;	# 36
  my $distance26=$47 if defined($47);	# 37
  my $distance27=$48 if defined($48);	# 38
  my $http_uri28=$49 if $49;		# 39
  my $http_urifast49=$50 if $50;
  my $http_urinocase40=$51 if $51;	# 40
  my $distance29=$52 if defined($52);	# 41
  my $distance30=$53 if defined($53);	# 42
  my $http_urifast54=$54 if $54;
  my $http_urinocase43=$55 if $55;	# 43
  my $distance31=$56 if defined($56);	# 44
  my $distance32=$57 if defined($57);	# 45
  my $http_uri33=$58 if $58;		# 46
  my $http_urifast58=$59 if $59;
  my $http_urinocase47=$60 if $60;	# 47
  my $distance34=$61 if defined($61);	# 48
  my $distance35=$62 if defined($62);	# 49
  my $http_urifast62=$63 if $63;
  my $http_urinocase50=$64 if $64;	# 50
  my $distance36=$65 if defined($65);	# 51
  my $distance37=$66 if defined($66);	# 52
  my $http_uri38=$67 if $67;		# 53
  my $http_urinocase54=$68 if $68;	# 54
  my $http_urinocase57=$57 if $57;	# 57
  my $http_uri43=$60 if $60;		# 60
  my $http_urinocase61=$61 if $61;	# 61
  my $http_urinocase64=$64 if $64;	# 64
  my $http_uri48=$67 if $67;		# 67
  my $http_urinocase68=$68 if $68;	# 68
  my $http_urinocase71=$71 if $71;	# 71
  my $http_uri53=$74 if $74;		# 74
  my $http_urinocase75=$75 if $75;	# 75
  my $http_urinocase78=$78 if $78;	# 78
  my $http_uri58=$81 if $81;		# 81
  my $http_urinocase82=$82 if $82;	# 82
  my $http_urinocase85=$85 if $85;	# 85
  my $http_uri63=$88 if $88;		# 88
  my $http_urinocase89=$89 if $89;	# 89
  my $http_urinocase92=$92 if $92;	# 92
  my $http_header68=$95 if $95;		# 95
  my $http_headernocase96=$96 if $96;	# 96
  my $http_headernocase99=$99 if $99;	# 99
  my $http_header121=$121 if $121;
  my $http_headerfast122=$122 if $122;
  my $http_headernocase123=$123 if $123;
  my $distance124=$124 if defined($124);
  my $distance125=$125 if defined($125);
  my $http_headerfast126=$126 if $126;
  my $http_headernocase127=$127 if $127;
  my $distance128=$128 if defined($128);
  my $distance129=$129 if defined($129);
  my $pcre_uri73=$130 if $130;		# 102
  my $http_header74=$131 if $131;	# 103
  my $http_headerfast132=$132 if $132;
  my $http_headernocase104=$133 if $133;# 104
  my $distance75=$134 if defined($134);	# 105
  my $distance76=$135 if defined($135);	# 106
  my $http_headerfast136=$136 if $136;
  my $http_headernocase107=$137 if $137;# 107
  my $distance77=$138 if defined($138);	# 108
  my $distance78=$139 if defined($139);	# 109
  my $pcre_agent79=$140 if $140;	# 110

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
  { $httpuricourt=$http_uri08; }
  elsif( $http_uri13_length >= $http_uri03_length && $http_uri13_length >= $http_uri08_length && $http_uri13_length >= $http_uri18_length && $http_uri13_length >= $http_uri23_length && $http_uri13_length >= $http_uri28_length && $http_uri13_length >= $http_uri33_length && $http_uri13_length >= $http_uri38_length && $http_uri13_length >= $http_uri43_length && $http_uri13_length >= $http_uri48_length && $http_uri13_length >= $http_uri53_length && $http_uri13_length >= $http_uri58_length && $http_uri13_length >= $http_uri63_length)
  { $httpuricourt=$http_uri13; }
  elsif( $http_uri18_length >= $http_uri03_length && $http_uri18_length >= $http_uri08_length && $http_uri18_length >= $http_uri13_length && $http_uri18_length >= $http_uri23_length && $http_uri18_length >= $http_uri28_length && $http_uri18_length >= $http_uri33_length && $http_uri18_length >= $http_uri38_length && $http_uri18_length >= $http_uri43_length && $http_uri18_length >= $http_uri48_length && $http_uri18_length >= $http_uri53_length && $http_uri18_length >= $http_uri58_length && $http_uri18_length >= $http_uri63_length)
  { $httpuricourt=$http_uri18; }
  elsif( $http_uri23_length >= $http_uri03_length && $http_uri23_length >= $http_uri08_length && $http_uri23_length >= $http_uri13_length && $http_uri23_length >= $http_uri18_length && $http_uri23_length >= $http_uri28_length && $http_uri23_length >= $http_uri33_length && $http_uri23_length >= $http_uri38_length && $http_uri23_length >= $http_uri43_length && $http_uri23_length >= $http_uri48_length && $http_uri23_length >= $http_uri53_length && $http_uri23_length >= $http_uri58_length && $http_uri23_length >= $http_uri63_length)
  { $httpuricourt=$http_uri23; }
  elsif( $http_uri28_length >= $http_uri03_length && $http_uri28_length >= $http_uri08_length && $http_uri28_length >= $http_uri13_length && $http_uri28_length >= $http_uri18_length && $http_uri28_length >= $http_uri23_length && $http_uri28_length >= $http_uri33_length && $http_uri28_length >= $http_uri38_length && $http_uri28_length >= $http_uri43_length && $http_uri28_length >= $http_uri48_length && $http_uri28_length >= $http_uri53_length && $http_uri28_length >= $http_uri58_length && $http_uri28_length >= $http_uri63_length)
  { $httpuricourt=$http_uri28; }
  elsif( $http_uri33_length >= $http_uri03_length && $http_uri33_length >= $http_uri08_length && $http_uri33_length >= $http_uri13_length && $http_uri33_length >= $http_uri18_length && $http_uri33_length >= $http_uri23_length && $http_uri33_length >= $http_uri28_length && $http_uri33_length >= $http_uri38_length && $http_uri33_length >= $http_uri43_length && $http_uri33_length >= $http_uri48_length && $http_uri33_length >= $http_uri53_length && $http_uri33_length >= $http_uri58_length && $http_uri33_length >= $http_uri63_length)
  { $httpuricourt=$http_uri33; }
  elsif( $http_uri38_length >= $http_uri03_length && $http_uri38_length >= $http_uri08_length && $http_uri38_length >= $http_uri13_length && $http_uri38_length >= $http_uri18_length && $http_uri38_length >= $http_uri23_length && $http_uri38_length >= $http_uri28_length && $http_uri38_length >= $http_uri33_length && $http_uri38_length >= $http_uri43_length && $http_uri38_length >= $http_uri48_length && $http_uri38_length >= $http_uri53_length && $http_uri38_length >= $http_uri58_length && $http_uri38_length >= $http_uri63_length)
  { $httpuricourt=$http_uri38; }
  elsif( $http_uri43_length >= $http_uri03_length && $http_uri43_length >= $http_uri08_length && $http_uri43_length >= $http_uri13_length && $http_uri43_length >= $http_uri18_length && $http_uri43_length >= $http_uri23_length && $http_uri43_length >= $http_uri28_length && $http_uri43_length >= $http_uri33_length && $http_uri43_length >= $http_uri38_length && $http_uri43_length >= $http_uri48_length && $http_uri43_length >= $http_uri53_length && $http_uri43_length >= $http_uri58_length && $http_uri43_length >= $http_uri63_length)
  { $httpuricourt=$http_uri43; }
  elsif( $http_uri48_length >= $http_uri03_length && $http_uri48_length >= $http_uri08_length && $http_uri48_length >= $http_uri13_length && $http_uri48_length >= $http_uri18_length && $http_uri48_length >= $http_uri23_length && $http_uri48_length >= $http_uri28_length && $http_uri48_length >= $http_uri33_length && $http_uri48_length >= $http_uri38_length && $http_uri48_length >= $http_uri43_length && $http_uri48_length >= $http_uri53_length && $http_uri48_length >= $http_uri58_length && $http_uri48_length >= $http_uri63_length)
  { $httpuricourt=$http_uri48; }
  elsif( $http_uri53_length >= $http_uri03_length && $http_uri53_length >= $http_uri08_length && $http_uri53_length >= $http_uri13_length && $http_uri53_length >= $http_uri18_length && $http_uri53_length >= $http_uri23_length && $http_uri53_length >= $http_uri28_length && $http_uri53_length >= $http_uri33_length && $http_uri53_length >= $http_uri38_length && $http_uri53_length >= $http_uri43_length && $http_uri53_length >= $http_uri48_length && $http_uri53_length >= $http_uri58_length && $http_uri53_length >= $http_uri63_length)
  { $httpuricourt=$http_uri53; }
  elsif( $http_uri58_length >= $http_uri03_length && $http_uri58_length >= $http_uri08_length && $http_uri58_length >= $http_uri13_length && $http_uri58_length >= $http_uri18_length && $http_uri58_length >= $http_uri23_length && $http_uri58_length >= $http_uri28_length && $http_uri58_length >= $http_uri33_length && $http_uri58_length >= $http_uri38_length && $http_uri58_length >= $http_uri43_length && $http_uri58_length >= $http_uri48_length && $http_uri58_length >= $http_uri53_length && $http_uri58_length >= $http_uri63_length)
  { $httpuricourt=$http_uri58; }
  elsif( $http_uri63_length >= $http_uri03_length && $http_uri63_length >= $http_uri08_length && $http_uri63_length >= $http_uri13_length && $http_uri63_length >= $http_uri18_length && $http_uri63_length >= $http_uri23_length && $http_uri63_length >= $http_uri28_length && $http_uri63_length >= $http_uri33_length && $http_uri63_length >= $http_uri38_length && $http_uri63_length >= $http_uri43_length && $http_uri63_length >= $http_uri48_length && $http_uri63_length >= $http_uri53_length && $http_uri63_length >= $http_uri58_length)
  { $httpuricourt=$http_uri63; }

  $http_uri03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri03; # (
  $http_uri03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri03; # )
  $http_uri03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri03; # *
  $http_uri03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri03; # +
  $http_uri03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri03; # -
  $http_uri03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri03; # .
  $http_uri03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri03; # /
  $http_uri03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri03; # ?
  $http_uri03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri03; # [
  $http_uri03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri03; # ]
  $http_uri03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri03; # ^
  $http_uri03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri03; # {
  $http_uri03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri03; # }
  $http_uri08 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri08; # (
  $http_uri08 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri08; # )
  $http_uri08 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri08; # *
  $http_uri08 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri08; # +
  $http_uri08 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri08; # -
  $http_uri08 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri08; # .
  $http_uri08 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri08; # /
  $http_uri08 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri08; # ?
  $http_uri08 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri08; # [
  $http_uri08 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri08; # ]
  $http_uri08 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri08; # ^
  $http_uri08 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri08; # {
  $http_uri08 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri08; # }
  $http_uri13 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri13; # (
  $http_uri13 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri13; # )
  $http_uri13 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri13; # *
  $http_uri13 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri13; # +
  $http_uri13 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri13; # -
  $http_uri13 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri13; # .
  $http_uri13 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri13; # /
  $http_uri13 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri13; # ?
  $http_uri13 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri13; # [
  $http_uri13 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri13; # ]
  $http_uri13 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri13; # ^
  $http_uri13 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri13; # {
  $http_uri13 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri13; # }
  $http_uri18 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri18; # (
  $http_uri18 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri18; # )
  $http_uri18 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri18; # *
  $http_uri18 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri18; # +
  $http_uri18 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri18; # -
  $http_uri18 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri18; # .
  $http_uri18 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri18; # /
  $http_uri18 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri18; # ?
  $http_uri18 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri18; # [
  $http_uri18 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri18; # ]
  $http_uri18 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri18; # ^
  $http_uri18 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri18; # {
  $http_uri18 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri18; # }
  $http_uri23 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri23; # (
  $http_uri23 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri23; # )
  $http_uri23 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri23; # *
  $http_uri23 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri23; # +
  $http_uri23 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri23; # -
  $http_uri23 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri23; # .
  $http_uri23 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri23; # /
  $http_uri23 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri23; # ?
  $http_uri23 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri23; # [
  $http_uri23 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri23; # ]
  $http_uri23 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri23; # ^
  $http_uri23 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri23; # {
  $http_uri23 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri23; # }
  $http_uri28 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri28; # (
  $http_uri28 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri28; # )
  $http_uri28 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri28; # *
  $http_uri28 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri28; # +
  $http_uri28 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri28; # -
  $http_uri28 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri28; # .
  $http_uri28 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri28; # /
  $http_uri28 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri28; # ?
  $http_uri28 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri28; # [
  $http_uri28 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri28; # ]
  $http_uri28 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri28; # ^
  $http_uri28 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri28; # {
  $http_uri28 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri28; # }
  $http_uri33 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri33; # (
  $http_uri33 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri33; # )
  $http_uri33 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri33; # *
  $http_uri33 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri33; # +
  $http_uri33 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri33; # -
  $http_uri33 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri33; # .
  $http_uri33 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri33; # /
  $http_uri33 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri33; # ?
  $http_uri33 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri33; # [
  $http_uri33 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri33; # ]
  $http_uri33 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri33; # ^
  $http_uri33 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri33; # {
  $http_uri33 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri33; # }
  $http_uri38 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri38; # (
  $http_uri38 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri38; # )
  $http_uri38 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri38; # *
  $http_uri38 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri38; # +
  $http_uri38 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri38; # -
  $http_uri38 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri38; # .
  $http_uri38 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri38; # /
  $http_uri38 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri38; # ?
  $http_uri38 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri38; # [
  $http_uri38 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri38; # ]
  $http_uri38 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri38; # ^
  $http_uri38 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri38; # {
  $http_uri38 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri38; # }
  $http_uri43 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri43; # (
  $http_uri43 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri43; # )
  $http_uri43 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri43; # *
  $http_uri43 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri43; # +
  $http_uri43 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri43; # -
  $http_uri43 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri43; # .
  $http_uri43 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri43; # /
  $http_uri43 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri43; # ?
  $http_uri43 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri43; # [
  $http_uri43 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri43; # ]
  $http_uri43 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri43; # ^
  $http_uri43 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri43; # {
  $http_uri43 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri43; # }
  $http_uri48 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri48; # (
  $http_uri48 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri48; # )
  $http_uri48 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri48; # *
  $http_uri48 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri48; # +
  $http_uri48 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri48; # -
  $http_uri48 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri48; # .
  $http_uri48 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri48; # /
  $http_uri48 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri48; # ?
  $http_uri48 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri48; # [
  $http_uri48 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri48; # ]
  $http_uri48 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri48; # ^
  $http_uri48 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri48; # {
  $http_uri48 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri48; # }
  $http_uri53 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri53; # (
  $http_uri53 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri53; # )
  $http_uri53 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri53; # *
  $http_uri53 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri53; # +
  $http_uri53 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri53; # -
  $http_uri53 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri53; # .
  $http_uri53 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri53; # /
  $http_uri53 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri53; # ?
  $http_uri53 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri53; # [
  $http_uri53 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri53; # ]
  $http_uri53 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri53; # ^
  $http_uri53 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri53; # {
  $http_uri53 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri53; # }
  $http_uri58 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri58; # (
  $http_uri58 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri58; # )
  $http_uri58 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri58; # *
  $http_uri58 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri58; # +
  $http_uri58 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri58; # -
  $http_uri58 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri58; # .
  $http_uri58 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri58; # /
  $http_uri58 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri58; # ?
  $http_uri58 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri58; # [
  $http_uri58 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri58; # ]
  $http_uri58 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri58; # ^
  $http_uri58 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri58; # {
  $http_uri58 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri58; # }
  $http_uri63 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri63; # (
  $http_uri63 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri63; # )
  $http_uri63 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri63; # *
  $http_uri63 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri63; # +
  $http_uri63 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri63; # -
  $http_uri63 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri63; # .
  $http_uri63 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri63; # /
  $http_uri63 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri63; # ?
  $http_uri63 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri63; # [
  $http_uri63 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri63; # ]
  $http_uri63 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri63; # ^
  $http_uri63 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri63; # {
  $http_uri63 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri63; # }
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
  #$pcre_uri73 =~ s/(?<!\x5C)\x24//g         if $pcre_uri73; # $
  $http_header74 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header74; # (
  $http_header74 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header74; # )
  $http_header74 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header74; # *
  $http_header74 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header74; # +
  $http_header74 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header74; # -
  $http_header74 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header74; # .
  $http_header74 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header74; # /
  $http_header74 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header74; # ?
  $http_header74 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header74; # [
  $http_header74 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header74; # ]
  $http_header74 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header74; # {
  $http_header74 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header74; # }
  #$http_header74 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header74; # ^
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
  while($http_header74 && $http_header74=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header74=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  # ne pas faire d'echappement sur la pcre ($pcre_agent79)
  my $abc1=0;
  my $httppcreagent=0;
  my $httpagentshort=0;
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
     if( $http_header74 && $http_header74 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser-Agent\: \E$/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser-Agent\:\E$/i ) { undef($http_header74) }
                           $http_header74 =~ s/\Q\x0D\x0A\E/\$/i if $http_header74;
  $pcre_agent79 =~ s/\Q^User\-Agent\x3A\x20\E/^/i if $pcre_agent79;
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
     if( $http_header74  && $http_header74 =~ s/\Q^Referer\x3A\x20\E/^/i ) { $pcrereferer = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\Q^Referer\x3A \E/^/i ) { $pcrereferer = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\QReferer\x3A\x20\E/^/i ) { $pcrereferer = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\QReferer\x3A \E/^/i ) { $pcrereferer = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\Q^Referer\x3A\E/^/i ) { $pcrereferer = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\QReferer\x3A\E/^/i ) { $pcrereferer = $http_header74; undef $http_header74 }

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
     if( $http_header74  && $http_header74 =~ s/\Q^Host\x3A\x20\E/^/i ) { $pcrehost = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\Q^Host\x3A \E/^/i ) { $pcrehost = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\QHost\x3A\x20\E/^/i ) { $pcrehost = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\QHost\x3A \E/^/i ) { $pcrehost = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\Q^Host\x3A\E/^/i ) { $pcrehost = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\QHost\x3A\E/^/i ) { $pcrehost = $http_header74; undef $http_header74 }

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
  if( $http_header68 && $http_header74 && $http_header121 && length($http_header68) >= (length($http_header74) or length($http_header121)) )
  {
   $httpagentshort= "$http_header68" if $http_header68;
  }
  elsif( $http_header68 && $http_header74 && $http_header121 && length($http_header74) >= (length($http_header68) or length($http_header121)) )
  {
   $httpagentshort= "$http_header74" if $http_header74;
  }
  elsif( $http_header68 && $http_header74 && $http_header121 && length($http_header121) >= (length($http_header68) or length($http_header74)) )
  {
   $httpagentshort= "$http_header121" if $http_header121;
  }
  elsif( $http_header68 && $http_header74 && !$http_header121 && length($http_header68) >= length($http_header74) )
  {
   $httpagentshort= "$http_header68" if $http_header68;
  }
  elsif( $http_header68 && $http_header74 && !$http_header121 && length($http_header74) >= length($http_header68) )
  {
   $httpagentshort= "$http_header74" if $http_header74;
  }
  elsif( $http_header68 && $http_header121 && !$http_header74 && length($http_header68) >= length($http_header121) )
  {
   $httpagentshort= "$http_header68" if $http_header68;
  }
  elsif( $http_header68 && $http_header121 && !$http_header74 && length($http_header121) >= length($http_header68) )
  {
   $httpagentshort= "$http_header121" if $http_header121;
  }
  elsif( $http_header74 && $http_header121 && !$http_header68 && length($http_header74) >= length($http_header121) )
  {
   $httpagentshort= "$http_header74" if $http_header74;
  }
  elsif( $http_header74 && $http_header121 && !$http_header68 && length($http_header121) >= length($http_header74) )
  {
   $httpagentshort= "$http_header121" if $http_header121;
  }
  elsif( $http_header68 && !$http_header74 && !$http_header121 )
  {
   $httpagentshort= "$http_header68" if $http_header68;
  }
  elsif( $http_header74 && !$http_header68 && !$http_header121 )
  {
   $httpagentshort= "$http_header74" if $http_header74;
  }
  elsif( $http_header121 && !$http_header68 && !$http_header74 )
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
  if( $pcre_agent79 && $http_header74 && $pcre_agent79=~/\Q$http_header74\E/i ) {
   undef $http_header74;
   print "ok trouvé grep74a\n" if $debug1;
  }
  elsif( $pcre_agent79 && $http_header74 && $http_header74=~s/\&/\\x26/g && $pcre_agent79=~/\Q$http_header74\E/i ) {
   undef $http_header74;
   print "ok trouvé grep74b\n" if $debug1;
  }
  elsif( $pcre_agent79 && $http_header74 && $http_header74=~s/\=/\\x3D/g && $pcre_agent79=~/\Q$http_header74\E/i ) {
   undef $http_header74;
   print "ok trouvé grep74c\n" if $debug1;
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

  # one header
  $httppcreagent= "$http_header68" if $http_header68 && !$http_header121 && !$http_header74 && !$pcre_agent79 && $http_header68 =~ /(?:\\|\^|\$)/;
  $httppcreagent= "$http_header121" if $http_header121 && !$http_header68 && !$http_header74 && !$pcre_agent79 && $http_header121 =~ /(?:\\|\^|\$)/;
  $httppcreagent= "$http_header74" if $http_header74 && !$http_header121 && !$http_header68 && !$pcre_agent79 && $http_header74 =~ /(?:\\|\^|\$)/;
  $httppcreagent= "$pcre_agent79" if $pcre_agent79 && !$http_header68 && !$http_header121 && !$http_header74;

  # two headers
  if( ($http_header68 && $http_header74 && !$http_header121) && (defined($distance75)||defined($distance76)||defined($distance77)||defined($distance78)) ) {
   $httppcreagent= "(?:$http_header68.*?$http_header74)" if $http_header68 && $http_header74;
  }
  elsif( ($http_header68 && $http_header74 && !$http_header121) && !(defined($distance75)||defined($distance76)||defined($distance77)||defined($distance78)) ) {
   $httppcreagent= "(?:$http_header68.*?$http_header74|$http_header74.*?$http_header68)" if $http_header68 && $http_header74;
  }
  elsif( ($http_header68 && !$http_header74 && $http_header121) && (defined($distance124)||defined($distance125)||defined($distance128)||defined($distance129)) ) {
   $httppcreagent= "(?:$http_header68.*?$http_header121)" if $http_header68 && $http_header121;
  }
  elsif( ($http_header68 && !$http_header74 && $http_header121) && !(defined($distance124)||defined($distance125)||defined($distance128)||defined($distance129)) ) {
   $httppcreagent= "(?:$http_header68.*?$http_header121|$http_header121.*?$http_header68)" if $http_header68 && $http_header121;
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

  # three headers
  if( (defined($distance75)||defined($distance76)||defined($distance77)||defined($distance78)) && (defined($distance124)||defined($distance125)||defined($distance128)||defined($distance129)) ) {
    $httppcreagent= "(?:$http_header68.*$http_header121.*$http_header74)" if $http_header68 && $http_header74 && $http_header121 && !$pcre_agent79;
  }
  elsif( !(defined($distance75)||defined($distance76)||defined($distance77)||defined($distance78)) && !(defined($distance124)||defined($distance125)||defined($distance128)||defined($distance129)) ) {
    $httppcreagent= "(?:$http_header68.*$http_header121.*$http_header74|$http_header68.*$http_header74.*$http_header121|$http_header74.*$http_header68.*$http_header121|$http_header74.*$http_header121.*$http_header68)" if $http_header68 && $http_header121 && $http_header74 && !$pcre_agent79;
    $httppcreagent= "(?:$http_header68.*$http_header121.*$pcre_agent79|$http_header68.*$pcre_agent79.*$http_header121|$pcre_agent79.*$http_header68.*$http_header121|$pcre_agent79.*$http_header121.*$http_header68)" if $http_header68 && $http_header121 && $pcre_agent79 && !$http_header74;
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
     $httppcreagent_nocase=$http_headerfast132  if $http_headerfast132;
     $httppcreagent_nocase=$http_headernocase104 if $http_headernocase104;
     $httppcreagent_nocase=$http_headerfast136  if $http_headerfast136;
     $httppcreagent_nocase=$http_headernocase107 if $http_headernocase107;

  if( $httpagentshort && $httppcreagent )
  {
   my $tempopcreagent = $httppcreagent;
   $tempopcreagent =~ s/\\(?!$)(?:x[a-f0-9]{2})?//g;
   if( $httpagentshort eq $tempopcreagent )
   {
    print "tempopcreagent: $tempopcreagent\n" if $debug1;
    undef $httppcreagent;
    undef $tempopcreagent;
   }
  }

  print "httpuricourt1: $etmsg1, ".lc($httpuricourt)."\n" if $debug1 && $httpuricourt;
  print "httpurilong1: $etmsg1, @tableauuri1\n" if $debug1 && @tableauuri1;
  print "tableaupcreuri1: $etmsg1, $abc1, $abc1_nocase\n" if $debug1 && $abc1;
  print "tableaupcreagent1: $etmsg1, $httppcreagent, $httppcreagent_nocase\n" if $debug1 && $httppcreagent;
  print "httpagentshort1: $etmsg1, ".lc($httpagentshort)."\n" if $debug1 && $httpagentshort;
  print "tableauhttpmethod1: $etmsg1, $http_method2, $http_methodnocase3\n" if $debug1 && $http_method2;
  print "httpreferer1: $etmsg1, ".lc($httpreferer)."\n" if $debug1 && $httpreferer;
  print "tableaupcrereferer1: $etmsg1, $pcrereferer\n" if $debug1 && $pcrereferer;
  print "httpurilongdistance1: $etmsg1, @tableauuridistance1\n" if $debug1 && @tableauuridistance1;
  print "httphost1: $etmsg1, ".lc($httphost)."\n" if $debug1 && $httphost;
  print "tableaupcrehost1: $etmsg1, $pcrehost\n" if $debug1 && $pcrehost;

  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt) ] if $httpuricourt;
  $hash{$etmsg1}{httpagentshort} = [ lc($httpagentshort) ] if $httpagentshort;
  $hash{$etmsg1}{httpmethod} = [ $http_method2, $http_methodnocase3 ] if $http_method2;
  $hash{$etmsg1}{httpreferer} = [ lc($httpreferer) ] if $httpreferer;
  $hash{$etmsg1}{pcrereferer} = [ $pcrereferer ] if $pcrereferer;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{pcreagent} = [ $httppcreagent, $httppcreagent_nocase ] if $httppcreagent;
  $hash{$etmsg1}{httpurilong} = [ @tableauuri1 ] if @tableauuri1;
  $hash{$etmsg1}{httpurilongdistance} = [ @tableauuridistance1 ] if @tableauuridistance1;
  $hash{$etmsg1}{httphost} = [ lc($httphost) ] if $httphost;
  $hash{$etmsg1}{pcrehost} = [ $pcrehost ] if $pcrehost;

  next;
 }

 # begin uricontent
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$urilen1)?(?:$httpmethod)?(?:$negateuricontent1)?\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:\s*(?:uri)?content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$pcreuri)?(?:$extracontentoptions)?$referencesidrev$/ )
 {
  my $etmsg1=$1;
  my $http_method2=0;
  my $http_methodnocase3=0;
  print "brut2: $_\n" if $debug1;
  #print "here2: 1: $1, 2: $2, 3: $3, 4: $4, 5: $5, 6: $6, 7: $7, 8: $8, 9: $9, 10: $10, 11: $11, 12: $12, 13: $13, 14: $14, 15: $15, 16: $16, 17: $17, 18: $18, 19: $19, 20: $20, 21: $21, 22: $22, 23: $23, 24: $24, 25: $25, 26: $26, 27: $27, 28: $28, 29: $29, 30: $30, 31: $31, 32: $32, 33: $33\n" if $debug1;

     $http_method2=$2 if $2;
     $http_methodnocase3=$3 if $3;

  my $http_uri03=$4 if $4;		# 4
  my $http_urifast5=$5 if $5;
  my $http_urinocase5=$6 if $6;		# 5
  my $http_header06=$8 if $8;		# 8
  my $http_headernocase9=$9 if $9;	# 9
  my $http_headernocase12=$12 if $12;	# 12
  my $http_uri11=$18 if $18;		# 15
  my $http_urifast19=$19 if $19;
  my $http_urinocase16=$20 if $20;	# 16
  my $http_uri14=$23 if $23;		# 19
  my $http_urifast24=$24 if $24;
  my $http_urinocase20=$25 if $25;	# 20
  my $http_uri17=$28 if $28;		# 23
  my $http_urifast29=$29 if $29;
  my $http_urinocase23=$30 if $30;	# 24
  my $pcre_uri20=$33 if $33;		# 27

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
  { $httpuricourt=$http_uri11; }
  elsif( $http_uri14_length >= $http_uri03_length && $http_uri14_length >= $http_uri11_length && $http_uri14_length >= $http_uri17_length )
  { $httpuricourt=$http_uri14; }
  elsif( $http_uri17_length >= $http_uri03_length && $http_uri17_length >= $http_uri11_length && $http_uri17_length >= $http_uri14_length )
  { $httpuricourt=$http_uri17; }

  $http_uri03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri03; # (
  $http_uri03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri03; # )
  $http_uri03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri03; # *
  $http_uri03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri03; # +
  $http_uri03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri03; # -
  $http_uri03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri03; # .
  $http_uri03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri03; # /
  $http_uri03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri03; # ?
  $http_uri03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri03; # [
  $http_uri03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri03; # ]
  $http_uri03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri03; # ^
  $http_uri03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri03; # {
  $http_uri03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri03; # }
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
  $http_uri11 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri11; # (
  $http_uri11 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri11; # )
  $http_uri11 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri11; # *
  $http_uri11 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri11; # +
  $http_uri11 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri11; # -
  $http_uri11 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri11; # .
  $http_uri11 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri11; # /
  $http_uri11 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri11; # ?
  $http_uri11 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri11; # [
  $http_uri11 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri11; # ]
  $http_uri11 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri11; # ^
  $http_uri11 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri11; # {
  $http_uri11 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri11; # }
  $http_uri14 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri14; # (
  $http_uri14 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri14; # )
  $http_uri14 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri14; # *
  $http_uri14 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri14; # +
  $http_uri14 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri14; # -
  $http_uri14 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri14; # .
  $http_uri14 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri14; # /
  $http_uri14 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri14; # ?
  $http_uri14 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri14; # [
  $http_uri14 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri14; # ]
  $http_uri14 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri14; # ^
  $http_uri14 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri14; # {
  $http_uri14 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri14; # }
  $http_uri17 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri17; # (
  $http_uri17 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri17; # )
  $http_uri17 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri17; # *
  $http_uri17 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri17; # +
  $http_uri17 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri17; # -
  $http_uri17 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri17; # .
  $http_uri17 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri17; # /
  $http_uri17 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri17; # ?
  $http_uri17 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri17; # [
  $http_uri17 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri17; # ]
  $http_uri17 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri17; # ^
  $http_uri17 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri17; # {
  $http_uri17 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri17; # }
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

  print "httpuricourt2: $etmsg1, ".lc($httpuricourt)."\n" if $debug1 && $httpuricourt;
  print "httpurilong2: $etmsg1, @tableauuri1\n" if $debug1 && @tableauuri1;
  print "tableaupcreuri2: $etmsg1, $abc1, $abc1_nocase\n" if $debug1 && $abc1;
  print "tableaupcreagent2: $etmsg1, $httppcreagent, $httppcreagent_nocase\n" if $debug1 && $httppcreagent;
  print "httpagentshort2: $etmsg1, ".lc($httpagentshort)."\n" if $debug1 && $httpagentshort;
  print "tableauhttpmethod2: $etmsg1, $http_method2, $http_methodnocase3\n" if $debug1 && $http_method2;
  print "tableaupcrereferer2: $etmsg1, $pcrereferer\n" if $debug1 && $pcrereferer;

  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt) ] if $httpuricourt;
  $hash{$etmsg1}{httpagentshort} = [ lc($httpagentshort) ] if $httpagentshort;
  $hash{$etmsg1}{httpmethod} = [ $http_method2, $http_methodnocase3 ] if $http_method2;
  $hash{$etmsg1}{pcrereferer} = [ $pcrereferer ] if $pcrereferer;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{pcreagent} = [ $httppcreagent, $httppcreagent_nocase ] if $httppcreagent;
  $hash{$etmsg1}{httpurilong} = [ @tableauuri1 ] if @tableauuri1;

  next;
 }

 # begin http_uri followed by a http_header
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flowbits1)?(?:$flow1)?(?:$httpmethod)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreuri)?(?:$extracontentoptions)?$referencesidrev$/ )
 {
  my $etmsg1=$1;
  my $http_method2=0;
  my $http_methodnocase3=0;
  print "brut3: $_\n" if $debug1;
  #print "here3: 1: $1, 2: $2, 3: $3, 4: $4, 5: $5, 6: $6, 7: $7, 8: $8, 9: $9, 10: $10, 11: $11, 12: $12, 13: $13, 14: $14, 15: $15, 16: $16, 17: $17, 18: $18, 19: $19, 20: $20, 21: $21, 22: $22, 23: $23, 24: $24, 25: $25, 26: $26, 27: $27, 28: $28, 29: $29, 30: $30, 31: $31, 32: $32, 33: $33, 34: $34, 35: $35, 36: $36, 37: $37, $38, $39, 40: $40\n" if $debug1;

     $http_method2=$2 if $2;
     $http_methodnocase3=$3 if $3;
  my $http_uri03=$4 if $4;			# 3
  my $http_urifast5=$5 if $5;
  my $http_urinocase5=$6 if $6;			# 5
  my $http_urifast9=$9 if $9;
  my $http_urinocase8=$10 if $10;		# 8
  my $http_header08=$13 if $13;			# 11
  my $http_headerfast14=$14 if $14;
  my $http_headernocase12=$15 if $15;		# 12
  my $http_headerfast18=$18 if $18;
  my $http_headernocase15=$19 if $19;		# 15
  my $http_uri13=$22 if $22;			# 18
  my $http_urifast23=$23 if $23;
  my $http_urinocase19=$24 if $24;		# 19
  my $distance14=$25 if defined($25);		# 20
  my $distance15=$26 if defined($26);		# 21
  my $http_urifast27=$27 if $27;
  my $http_urinocase22=$28 if $28;		# 22
  my $distance16=$29 if defined($29);		# 23
  my $distance17=$30 if defined($30);		# 24
  my $http_header18=$31 if $31;			# 25
  my $http_headerfast32=$32 if $32;
  my $http_headernocase26=$33 if $33;		# 26
  my $distance34=$34 if defined($34);
  my $distance35=$35 if defined($35);
  my $http_headerfast36=$36 if $36;
  my $http_headernocase29=$37 if $37;		# 29
  my $distance38=$38 if defined($38);
  my $distance39=$39 if defined($39);
  my $pcre_uri23=$40 if $40;			# 32

  # check what is http_uri best length ?
  my $httpuricourt=0;
  my $http_uri03_length=0;
  my $http_uri13_length=0;
  $http_uri03_length=length($http_uri03) if $http_uri03;
  $http_uri13_length=length($http_uri13) if $http_uri13;
  if( $http_uri03_length >= $http_uri13_length )
  { $httpuricourt=$http_uri03; }
  elsif( $http_uri13_length >= $http_uri03_length )
  { $httpuricourt=$http_uri13; }

  $http_uri03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri03; # (
  $http_uri03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri03; # )
  $http_uri03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri03; # *
  $http_uri03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri03; # +
  $http_uri03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri03; # -
  $http_uri03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri03; # .
  $http_uri03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri03; # /
  $http_uri03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri03; # ?
  $http_uri03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri03; # [
  $http_uri03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri03; # ]
  $http_uri03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri03; # ^
  $http_uri03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri03; # {
  $http_uri03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri03; # }
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
  $http_uri13 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri13; # (
  $http_uri13 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri13; # )
  $http_uri13 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri13; # *
  $http_uri13 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri13; # +
  $http_uri13 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri13; # -
  $http_uri13 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri13; # .
  $http_uri13 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri13; # /
  $http_uri13 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri13; # ?
  $http_uri13 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri13; # [
  $http_uri13 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri13; # ]
  $http_uri13 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri13; # ^
  $http_uri13 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri13; # {
  $http_uri13 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri13; # }
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

  print "httpuricourt3: $etmsg1, ".lc($httpuricourt)."\n" if $debug1 && $httpuricourt;
  print "httpurilong3: $etmsg1, @tableauuri1\n" if $debug1 && @tableauuri1;
  print "tableaupcreuri3: $etmsg1, $abc1, $abc1_nocase\n" if $debug1 && $abc1;
  print "tableaupcreagent3: $etmsg1, $httppcreagent, $httppcreagent_nocase\n" if $debug1 && $httppcreagent;
  print "httpagentshort3: $etmsg1, ".lc($httpagentshort)."\n" if $debug1 && $httpagentshort;
  print "tableauhttpmethod3: $etmsg1, $http_method2, $http_methodnocase3\n" if $debug1 && $http_method2;
  print "tableaupcrereferer3: $etmsg1, $pcrereferer\n" if $debug1 && $pcrereferer;

  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt) ] if $httpuricourt;
  $hash{$etmsg1}{httpagentshort} = [ lc($httpagentshort) ] if $httpagentshort;
  $hash{$etmsg1}{httpmethod} = [ $http_method2, $http_methodnocase3 ] if $http_method2;
  $hash{$etmsg1}{pcrereferer} = [ $pcrereferer ] if $pcrereferer;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{pcreagent} = [ $httppcreagent, $httppcreagent_nocase ] if $httppcreagent;
  $hash{$etmsg1}{httpurilong} = [ @tableauuri1 ] if @tableauuri1;

  next;
 }

 # begin http_header
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$urilen1)?(?:$httpmethod)?(?:$negateuricontent1)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreuri)?(?:$pcreagent)?(?:$extracontentoptions)?$referencesidrev$/ )
 {
  my $etmsg1=$1;
  my $http_method2=0;
  my $http_methodnocase3=0;
  print "brut4: $_\n" if $debug1;
  #print "here4: 1: $1, 2: $2, 3: $3, 4: $4, 5: $5, 6: $6, 7: $7, 8: $8, 9: $9, 10: $10, 11: $11, 12: $12, 13: $13, 14: $14, 15: $15, 16: $16, 17: $17, 18: $18, 19: $19, 20: $20, 21: $21, 22: $22, 23: $23, 24: $24, 25: $25, 26: $26, 27: $27, 28: $28, 29: $29, 30: $30, 31: $31, 32: $32, 33: $33, 34: $34, 35: $35, 36: $36, 37: $37, $38, $39, 40: $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, 50: $50, $51, $52, $53, 54: $54, $55, $56, $57, $58, 59: $59\n" if $debug1;

     $http_method2=$2 if $2;
     $http_methodnocase3=$3 if $3;
  my $http_header03=$4 if $4;		# 4
  my $http_headerfast5=$5 if $5;
  my $http_headernocase5=$6 if $6;	# 5
  my $http_headerfast9=$9 if $9;
  my $http_headernocase8=$10 if $10;	# 8
  my $http_uri08=$13 if $13;		# 11
  my $http_urifast14=$14 if $14;
  my $http_urinocase12=$15 if $15;	# 12
  my $http_urifast18=$18 if $18;
  my $http_urinocase15=$19 if $19;	# 15
  my $http_header13=$22 if $22;		# 18
  my $http_headerfast23=$23 if $23;
  my $http_headernocase19=$24 if $24;	# 19
  my $distance14=$25 if defined($25);	# 20
  my $distance15=$26 if defined($26);	# 21
  my $http_headerfast27=$27 if $27;
  my $http_headernocase22=$28 if $28;	# 22
  my $distance16=$29 if defined($29);	# 23
  my $distance17=$30 if defined($30);	# 24
  my $http_uri18=$31 if $31;		# 25
  my $http_urifast32=$32 if $32;
  my $http_urinocase25=$33 if $33;	# 26
  my $distance19=$34 if defined($34);	# 27
  my $distance20=$35 if defined($35);	# 28
  my $http_urifast36=$36 if $36;
  my $http_urinocase28=$37 if $37;	# 29
  my $distance21=$38 if defined($38);	# 30
  my $distance22=$39 if defined($39);	# 31
  my $http_header23=$40 if $40;		# 32
  my $http_headerfast41=$41 if $41;
  my $http_headernocase32=$42 if $42;	# 33
  my $distance24=$43 if defined($43);	# 34
  my $distance25=$44 if defined($44);	# 35
  my $http_headerfast45=$45 if $45;
  my $http_headernocase35=$46 if $46;	# 36
  my $distance26=$47 if defined($47);	# 37
  my $distance27=$48 if defined($48);	# 38
  my $http_uri28=$49 if $49;		# 39
  my $http_urifast50=$50 if $50;
  my $http_urinocase39=$51 if $51;	# 40
  my $distance29=$52 if defined($52);	# 41
  my $distance30=$53 if defined($53);	# 42
  my $http_urifast54=$54 if $54;
  my $http_urinocase42=$55 if $55;	# 43
  my $distance31=$56 if defined($56);	# 44
  my $distance32=$57 if defined($57);	# 45
  my $pcre_uri33=$58 if $58;		# 46
  my $pcre_agent34=$59 if $59;		# 47

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
  { $httpuricourt=$http_uri18; }
  elsif( $http_uri28_length >= $http_uri08_length && $http_uri28_length >= $http_uri18_length )
  { $httpuricourt=$http_uri28; }

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
  $http_uri08 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri08; # (
  $http_uri08 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri08; # )
  $http_uri08 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri08; # *
  $http_uri08 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri08; # +
  $http_uri08 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri08; # -
  $http_uri08 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri08; # .
  $http_uri08 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri08; # /
  $http_uri08 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri08; # ?
  $http_uri08 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri08; # [
  $http_uri08 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri08; # ]
  $http_uri08 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri08; # ^
  $http_uri08 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri08; # {
  $http_uri08 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri08; # }
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
  $http_uri18 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri18; # (
  $http_uri18 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri18; # )
  $http_uri18 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri18; # *
  $http_uri18 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri18; # +
  $http_uri18 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri18; # -
  $http_uri18 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri18; # .
  $http_uri18 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri18; # /
  $http_uri18 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri18; # ?
  $http_uri18 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri18; # [
  $http_uri18 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri18; # ]
  $http_uri18 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri18; # ^
  $http_uri18 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri18; # {
  $http_uri18 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri18; # }
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
  $http_uri28 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri28; # (
  $http_uri28 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri28; # )
  $http_uri28 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri28; # *
  $http_uri28 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri28; # +
  $http_uri28 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri28; # -
  $http_uri28 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri28; # .
  $http_uri28 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri28; # /
  $http_uri28 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri28; # ?
  $http_uri28 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri28; # [
  $http_uri28 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri28; # ]
  $http_uri28 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri28; # ^
  $http_uri28 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri28; # {
  $http_uri28 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri28; # }
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
  $httppcreagent= "$http_header03" if $http_header03 && !$http_header13 && !$http_header23 && !$pcre_agent34;
  $httppcreagent= "$http_header13" if $http_header13 && !$http_header03 && !$http_header23 && !$pcre_agent34;
  $httppcreagent= "$http_header23" if $http_header23 && !$http_header03 && !$http_header13 && !$pcre_agent34;
  $httppcreagent= "$pcre_agent34" if $pcre_agent34 && !$http_header03 && !$http_header13 && !$http_header23;
  unless( $httppcreagent && ($httppcreagent =~/(?:\\|\^|\$)/) ) { $httppcreagent=0 }

  # one uri
  #$abc1= "$http_uri08" if $http_uri08 && !$http_uri18 && !$http_uri28;
  #$abc1= "$http_uri18" if $http_uri18 && !$http_uri08 && !$http_uri28;
  #$abc1= "$http_uri28" if $http_uri28 && !$http_uri08 && !$http_uri18;
  $abc1= "$pcre_uri33" if $pcre_uri33 && !$http_uri08 && !$http_uri18;

  # two headers
  if( (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
   $httppcreagent= "(?:$http_header03.*?$http_header13)" if $http_header03 && $http_header13 && !$http_header23 && !$pcre_agent34;
  }
  elsif( !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
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
   $httppcreagent= "(?:$http_header03.*$http_header13.*$http_header23)" if $http_header03 && $http_header13 && $http_header23 && !$pcre_agent34;
  }
  elsif( !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
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
   $httppcreagent= "(?:$http_header03.*$http_header13.*$http_header23.*$pcre_agent34|$http_header03.*$http_header13.*$pcre_agent34.*$http_header23|$http_header03.*$http_header23.*$http_header13.*$pcre_agent34|$http_header03.*$http_header23.*$pcre_agent34.*$http_header13|$http_header13.*$http_header23.*$pcre_agent34.*$http_header03|$http_header13.*$http_header23.*$http_header03.*$pcre_agent34|$http_header13.*$http_header03.*$http_header23.*$pcre_agent34|$http_header13.*$http_header03.*$pcre_agent34.*$http_header23|$http_header23.*$http_header03.*$http_header13.*$pcre_agent34|$http_header23.*$http_header03.*$pcre_agent34.*$http_header13|$http_header23.*$http_header13.*$pcre_agent34.*$http_header03|$http_header23.*$http_header13.*$http_header03.*$pcre_agent34|$pcre_agent34.*$http_header03.*$http_header13.*$http_header23|$pcre_agent34.*$http_header03.*$http_header23.*$http_header13|$pcre_agent34.*$http_header23.*$http_header03.*$http_header13|$pcre_agent34.*$http_header23.*$http_header13.*$http_header03)" if $http_header03 && $http_header13 && $http_header23 && $pcre_agent34;

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
   $tempopcreagent =~ s/\\(?!$)(?:x[a-f0-9]{2})?//g;
   if( $httpagentshort eq $tempopcreagent )
   {
    print "tempopcreagent: $tempopcreagent\n" if $debug1;
    undef $httppcreagent;
    undef $tempopcreagent;
   }
  }

  print "httpuricourt4: $etmsg1, ".lc($httpuricourt)."\n" if $debug1 && $httpuricourt;
  print "httpurilong4: $etmsg1, @tableauuri1\n" if $debug1 && @tableauuri1;
  print "tableaupcreuri4: $etmsg1, $abc1, $abc1_nocase\n" if $debug1 && $abc1;
  print "tableaupcreagent4: $etmsg1, $httppcreagent, $httppcreagent_nocase\n" if $debug1 && $httppcreagent;
  print "httpagentshort4: $etmsg1, ".lc($httpagentshort)."\n" if $debug1 && $httpagentshort;
  print "tableauhttpmethod4: $etmsg1, $http_method2, $http_methodnocase3\n" if $debug1 && $http_method2;
  print "httpreferer4: $etmsg1, ".lc($httpreferer)."\n" if $debug1 && $httpreferer;
  print "tableaupcrereferer4: $etmsg1, $pcrereferer\n" if $debug1 && $pcrereferer;
  print "tableauhttpcookie4: $etmsg1, $http_cookie\n" if $debug1 && $http_cookie;
  print "tableaupcrecookie4: $etmsg1, $cookiepcre\n" if $debug1 && $cookiepcre;
  print "httphost4: $etmsg1, ".lc($httphost)."\n" if $debug1 && $httphost;
  print "tableaupcrehost4: $etmsg1, $pcrehost\n" if $debug1 && $pcrehost;

  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt) ] if $httpuricourt;
  $hash{$etmsg1}{httpagentshort} = [ lc($httpagentshort) ] if $httpagentshort;
  $hash{$etmsg1}{httpmethod} = [ $http_method2, $http_methodnocase3 ] if $http_method2;
  $hash{$etmsg1}{httpreferer} = [ lc($httpreferer) ] if $httpreferer;
  $hash{$etmsg1}{pcrereferer} = [ $pcrereferer ] if $pcrereferer;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{pcreagent} = [ $httppcreagent, $httppcreagent_nocase ] if $httppcreagent;
  $hash{$etmsg1}{httpcookie} = [ $http_cookie ] if $http_cookie;
  $hash{$etmsg1}{pcrecookie} = [ $cookiepcre ] if $cookiepcre;
  $hash{$etmsg1}{httpurilong} = [ @tableauuri1 ] if @tableauuri1;
  $hash{$etmsg1}{httphost} = [ lc($httphost) ] if $httphost;
  $hash{$etmsg1}{pcrehost} = [ $pcrehost ] if $pcrehost;

  next;
 }


 # begin http_uri followed by http_cookie
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$httpmethod)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)?\s*http_uri\;(?:$contentoptions1)?(?:$negateuricontent1)?)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)?\s*http_cookie\;(?:$contentoptions1)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:$pcreuri)?(?:$pcrecookie)?(?:$extracontentoptions)?$referencesidrev$/ )
 {
  my $etmsg1=$1;
  my $http_method2=0;
  my $http_methodnocase3=0;
  print "brut5: $_\n" if $debug1;
  #print "here5: $1, $2, $3, $4, 5: $5, $6, $7, $8, $9, 10: $10, 11: $11, $12, 13: $13, $14, 15: $15, $16, $17, $18, $19, 20: $20, $21, $22\n" if $debug1;

     $http_method2=$2 if $2;
     $http_methodnocase3=$3 if $3;
  my $http_uri03=$4 if $4;
  my $http_urinocase5=$6 if $6;
  my $http_urinocase8=$10 if $10;
  my $http_cookie=$13 if $13;
  my $http_cookienocase12=$15 if $15;
  my $http_cookienocase15=$19 if $19;
  my $pcre_uri13=$22 if $22;
  my $cookiepcre=$23 if $23;

  # check what is http_uri best length ?
  my $httpuricourt=0;
     $httpuricourt=$http_uri03 if $http_uri03;

  $http_uri03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri03; # (
  $http_uri03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri03; # )
  $http_uri03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri03; # *
  $http_uri03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri03; # +
  $http_uri03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri03; # -
  $http_uri03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri03; # .
  $http_uri03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri03; # /
  $http_uri03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri03; # ?
  $http_uri03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri03; # [
  $http_uri03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri03; # ]
  $http_uri03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri03; # ^
  $http_uri03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri03; # {
  $http_uri03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri03; # }
  $http_cookie =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_cookie; # (
  $http_cookie =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_cookie; # )
  $http_cookie =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_cookie; # *
  $http_cookie =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_cookie; # +
  $http_cookie =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_cookie; # -
  $http_cookie =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_cookie; # .
  $http_cookie =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_cookie; # /
  $http_cookie =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_cookie; # ?
  $http_cookie =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_cookie; # [
  $http_cookie =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_cookie; # ]
  $http_cookie =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_cookie; # ^
  $http_cookie =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_cookie; # {
  $http_cookie =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_cookie; # }
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

  if( $pcre_uri13 )
  {
   $pcre_uri13 =~ s/^\^\\\//\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\\//i;
   $pcre_uri13 =~ s/^\^\\x2F/\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\x2F/i;
  }

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

  print "httpuricourt5: $etmsg1, ".lc($httpuricourt)."\n" if $debug1 && $httpuricourt;
  print "tableaupcreuri5: $etmsg1, $abc1, $abc1_nocase\n" if $debug1 && $abc1;
  print "tableauhttpmethod5: $etmsg1, $http_method2, $http_methodnocase3\n" if $debug1 && $http_method2;
  print "tableauhttpcookie5: $etmsg1, $http_cookie, $http_cookie_nocase\n" if $debug1 && $http_cookie;
  print "tableaupcrecookie5: $etmsg1, $cookiepcre, $http_cookie_nocase\n" if $debug1 && $cookiepcre;

  #push( @tableauuricontent, ("$etmsg1", "$http_method2", "$http_methodnocase3" , "", "",    , "", "$abc1", "$abc1_nocase") ) if $abc1;

  $hash{$etmsg1}{httpuricourt} = [ lc($httpuricourt) ] if $httpuricourt;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{httpmethod} = [ $http_method2, $http_methodnocase3 ] if $http_method2;
  $hash{$etmsg1}{httpcookie} = [ $http_cookie, $http_cookie_nocase ] if $http_cookie;
  $hash{$etmsg1}{pcrecookie} = [ $cookiepcre, $http_cookie_nocase ] if $cookiepcre;

  $http_cookie=0 if $http_cookie;
  $cookiepcre=0 if $cookiepcre;

  next;
 }

#alert ip any any -> 103.13.232.232 any (msg:"Shadowserver C&C List: 103.13.232.232"; reference:url,rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt; classtype:misc-activity; sid:9990001; rev:1;)
 elsif( $_=~ /^\s*alert\s+ip\s+\S+\s+\S+\s+\-\>\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d+)?)\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;[^\n]*?$referencesidrev$/ )
 {
  my $etmsg1=$2;
  my $remote_ip=$1;
  print "brut6: $_\n" if $debug1;
  #print "here6: $1, $2, $3, $4, 5: $5, $6, $7, $8, $9, 10: $10, 11: $11, $12, 13: $13, $14, 15: $15, $16, $17, $18, $19, 20: $20, $21, $22\n" if $debug1;

  print "remoteip6: $etmsg1, $remote_ip\n" if $debug1 && $remote_ip;

  $hash{$etmsg1}{remoteip} = [ $remote_ip ] if $remote_ip;

  $remote_ip=0 if $remote_ip;

  next;
 }

 else
 {
  print "erreur parsing signature: $_\n" if $debug1;
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

# elsif ( $output_escape =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\t|\\t)+(\S+)(?:\t|\\t)+(.*?)(?:\t|\\t)+(\d{4}\-\d{2}\-\d{2})(?:\t|\\t)+(\d{2}\:\d{2}\:\d{2})(?:\t|\\t)+([0-9a-zA-Z\-\_]+)(?:\t|\\t)+(.*?)(?:\t|\\t)+(.*?)(?:\t|\\t)+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+.*?(?:\t|\\t)+([0-9a-zA-Z\-\_]+)(?:\t|\\t)+(.*?)(?:\t|\\t)+\S+(?:\t|\\t)+(\d+)/) {
 elsif ( $output_escape =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\t|\\t)+(\S+)(?:\t|\\t)+(.*?)(?:\t|\\t)+(\d{4}\-\d{2}\-\d{2})(?:\t|\\t)+(\d{2}\:\d{2}\:\d{2})(?:\t|\\t)+([0-9a-zA-Z\-\_]+)(?:\t|\\t)+(.*?)(?:\t|\\t)+(.*?)(?:\t|\\t)+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+.*?(?:\t|\\t)+([0-9a-zA-Z\-\_]+)(?:\t|\\t)+(?:\w+\:\/\/)?([^\/]*?)(\/.*?)?(?:\t|\\t)+\S+(?:\t|\\t)+(\d+)/) {
#  $client_hostname_ip=$1; $client_username=$2; $client_http_useragent=$3; $timestamp_central=$4." ".$5; $server_hostname_ip=$6; $client_http_referer=$7; $client_http_method=$9; $client_http_uri=$10; $http_reply_code=$11;
  $client_hostname_ip=$1; $client_username=$2; $client_http_useragent=$3; $timestamp_central=$4." ".$5; $server_hostname_ip=$6; $client_http_referer=$7; $client_http_method=$9; $client_http_host=$10; $client_http_uri=$11; $http_reply_code=$12;
  # https/ssl-tunnel:
  #if( $11 eq "-" && $8 ne "-" )
  #{
  # $client_http_uri=$8;
  #}
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


 else {
  if( $syslogsock )
  {
   print $syslogsock "$host etplc: aucun parser ne correspond au motif !!! $output_escape\n";
  }
  else
  {
   print "aucun parser ne correspond au motif !!! $output_escape\n";
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
     if( $hash{$etmsg}{"httpuricourt"}[0] && $client_http_uri && index(lc($client_http_uri), $hash{$etmsg}{"httpuricourt"}[0]) != -1 )
     {
      print "ici2: ",$hash{$etmsg}{"httpuricourt"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpuricourt"}[0];
      $founduricourt1=1;
     }
     elsif( $hash{$etmsg}{"httpuricourt"}[0] )
     {
      print "uri not found2: jump (",$hash{$etmsg}{"httpuricourt"}[0],")\n" if $debug2;
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
     if( $hash{$etmsg}{"httpagentshort"}[0] && $client_http_useragent && index(lc($client_http_useragent), $hash{$etmsg}{"httpagentshort"}[0]) != -1 )
     {
      print "ici4: ",$hash{$etmsg}{"httpagentshort"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpagentshort"}[0];
      $foundagent=1;
     }
     elsif( $hash{$etmsg}{"httpagentshort"}[0] )
     {
      print "agent not found: jump (",$hash{$etmsg}{"httpagentshort"}[0],")\n" if $debug2;
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
    if( $syslogsock && ($foundmethod or $founduricourt1 or $foundurilong1 or $foundurilongdistance1 or $foundagent or $foundreferer or $foundcookie or $foundpcrereferer or $foundpcreagent or $foundpcrecookie or $foundpcreuri or $foundremoteip or $foundhost or $foundpcrehost) )
    {
     lock($queue);
     my $tutu='';
     print $syslogsock "$host etplc: ok trouvé: ";
     print $syslogsock "timestamp: $timestamp_central, " if $timestamp_central;
     print $syslogsock "server_hostname_ip: $server_hostname_ip, " if $server_hostname_ip;
     print $syslogsock "client_hostname_ip: $client_hostname_ip, " if $client_hostname_ip;
     print $syslogsock "client_username: $client_username, " if $client_username;
     print $syslogsock "client_http_method: $client_http_method, " if $client_http_method;
     print $syslogsock "client_http_uri: $client_http_uri, " if $client_http_uri;
     print $syslogsock "client_http_useragent: $client_http_useragent, " if $client_http_useragent;
     print $syslogsock "client_http_referer: $client_http_referer, " if $client_http_referer;
     print $syslogsock "client_http_cookie: $client_http_cookie, " if $client_http_cookie;
     print $syslogsock "client_http_host: $client_http_host, " if $client_http_host;
     print $syslogsock "http_reply_code: $http_reply_code, " if $http_reply_code;
     print $syslogsock "server_remote_ip: $server_remote_ip, " if $server_remote_ip;
     print $syslogsock "etmsg: $etmsg" if $etmsg;

     #print $syslogsock ", etmethod: ",$hash{$etmsg}{"httpmethod"}[0] if $foundmethod;
     $tutu=$hash{$etmsg}{"httpmethod"}[0];
     print $syslogsock ", etmethod: $tutu" if $foundmethod;

     #print $syslogsock ", eturishort: ",$hash{$etmsg}{"httpuricourt"}[0] if $founduricourt1;
     $tutu=$hash{$etmsg}{"httpuricourt"}[0];
     print $syslogsock ", eturishort: $tutu" if $founduricourt1;

     #print $syslogsock ", eturilong: ",$hash{$etmsg}{"httpurilong"}[0] if $foundurilong1;
     $tutu=$hash{$etmsg}{"httpurilong"}[0];
     print $syslogsock ", eturilong: $tutu" if $foundurilong1;

     #if( $foundurilongdistance1 ){ print $syslogsock ", eturilongdistance: "; print $syslogsock "$_ ",foreach values $hash{$etmsg}{"httpurilongdistance"} }
     if( $foundurilongdistance1 ){ print $syslogsock ", eturilongdistance: "; $tutu.= "$_ ",foreach values $hash{$etmsg}{"httpurilongdistance"}; print $syslogsock $tutu; }

     #print $syslogsock ", etagent: ",$hash{$etmsg}{"httpagentshort"}[0] if $foundagent;
     $tutu=$hash{$etmsg}{"httpagentshort"}[0];
     print $syslogsock ", etagent: $tutu" if $foundagent;

     #print $syslogsock ", etreferer: ",$hash{$etmsg}{"httpreferer"}[0] if $foundreferer;
     $tutu=$hash{$etmsg}{"httpreferer"}[0];
     print $syslogsock ", etreferer: $tutu" if $foundreferer;

     #print $syslogsock ", etcookie: ",$hash{$etmsg}{"httpcookie"}[0] if $foundcookie;
     $tutu=$hash{$etmsg}{"httpcookie"}[0];
     print $syslogsock ", etcookie: $tutu" if $foundcookie;

     #print $syslogsock ", etpcrereferer: ",$hash{$etmsg}{"pcrereferer"}[0] if $foundpcrereferer;
     $tutu=$hash{$etmsg}{"pcrereferer"}[0];
     print $syslogsock ", etpcrereferer: $tutu" if $foundpcrereferer;

     #print $syslogsock ", etpcreagent: ",$hash{$etmsg}{"pcreagent"}[0] if $foundpcreagent;
     $tutu=$hash{$etmsg}{"pcreagent"}[0];
     print $syslogsock ", etpcreagent: $tutu" if $foundpcreagent;

     #print $syslogsock ", etpcrecookie: ",$hash{$etmsg}{"pcrecookie"}[0] if $foundpcrecookie;
     $tutu=$hash{$etmsg}{"pcrecookie"}[0];
     print $syslogsock ", etpcrecookie: $tutu" if $foundpcrecookie;

     #print $syslogsock ", etpcreuri: ",$hash{$etmsg}{"pcreuri"}[0] if $foundpcreuri;
     $tutu=$hash{$etmsg}{"pcreuri"}[0];
     print $syslogsock ", etpcreuri: $tutu" if $foundpcreuri;

     #print $syslogsock ", etremoteip: ",$hash{$etmsg}{"remoteip"}[0] if $foundremoteip;
     $tutu=$hash{$etmsg}{"remoteip"}[0];
     print $syslogsock ", etremoteip: $tutu" if $foundremoteip;

     #print $syslogsock ", ethost: ",$hash{$etmsg}{"httphost"}[0] if $foundhost;
     $tutu=$hash{$etmsg}{"httphost"}[0];
     print $syslogsock ", ethost: $tutu" if $foundhost;

     #print $syslogsock ", etpcrehost: ",$hash{$etmsg}{"pcrehost"}[0] if $foundpcrehost;
     $tutu=$hash{$etmsg}{"pcrehost"}[0];
     print $syslogsock ", etpcrehost: $tutu" if $foundpcrehost;

     print $syslogsock "\n";
    }
    elsif( $foundmethod or $founduricourt1 or $foundurilong1 or $foundurilongdistance1 or $foundagent or $foundreferer or $foundcookie or $foundpcrereferer or $foundpcreagent or $foundpcrecookie or $foundpcreuri or $foundremoteip or $foundhost or $foundpcrehost)
    {
     lock($queue);
     print "ok trouvé: ";
     print "timestamp: $timestamp_central, " if $timestamp_central;
     print "server_hostname_ip: $server_hostname_ip, " if $server_hostname_ip;
     print "client_hostname_ip: $client_hostname_ip, " if $client_hostname_ip;
     print "client_username: $client_username, " if $client_username;
     print "client_http_method: $client_http_method, " if $client_http_method;
     print "client_http_uri: $client_http_uri, " if $client_http_uri;
     print "client_http_useragent: $client_http_useragent, " if $client_http_useragent;
     print "client_http_referer: $client_http_referer, " if $client_http_referer;
     print "client_http_cookie: $client_http_cookie, " if $client_http_cookie;
     print "client_http_host: $client_http_host, " if $client_http_host;
     print "http_reply_code: $http_reply_code, " if $http_reply_code;
     print "server_remote_ip: $server_remote_ip, " if $server_remote_ip;
     print "etmsg: $etmsg" if $etmsg;
     print ", etmethod: ",$hash{$etmsg}{"httpmethod"}[0] if $foundmethod;
     print ", eturishort: ",$hash{$etmsg}{"httpuricourt"}[0] if $founduricourt1;
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
     print "\n";
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

close FILEEMERGINGTHREATS;
exit(0);

