#!/usr/bin/env python2
# -*- coding: utf-8 -*-

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

# ChangeLog:
#  9jan2015: merge python v2 and v3 and fix apache format logs, thx Alexandre
# 28dec2014: add remote_ip bluecoat main format logs v6.5.5
# 27dec2014: fix bluecoat main format logs v6.5.5, thx Damien
# 17dec2014: fix apache logs + httpreferer4
#  5dec2014: fix apache logs, thx Eric! + fixed category
# 16nov2014: add initial Remote IP option
# 15oct2014: enhance debug
#  8oct2014: enhance cookie - synchro perl
#  7oct2014: add search referer content optimization - synchro perl
#  6oct2014: add short testing for performance on Referer and User-Agent: - - synchro perl
#  5oct2014: add optimization on two or more content with distance without pcre - synchro perl
# 21aug2014: modify x.lower()
#  9aug2014: fix CR LF injection
# 29jul2014: enhance virtual syslog over socket and file parser
# 24jul2014: enhance pcre Squid (thx @tikums)
# 28Jun2014: one small fix
# 25Jun2014: added Proxy McAfee WebGateway v7.2.x logs
# 24May2014: fix a bug on brut1 http_uri03
# 05May2014: fix tableaupcrereferer4 $
# 10Apr2014: fix brut1 uri distance
# 01Apr2014: enhanced cookie

#import re
# sudo yum install python-devel
# sudo yum install python-pip
# sudo pip install regex :
import regex as re
import sys
import urllib # unquote
import multiprocessing # Pool
import argparse
from argparse import RawTextHelpFormatter
import socket # for sysloging
import gzip

####################################################################################################

# global variables:
timestamp_central=0; server_hostname_ip=0; timestamp_unix=0; client_hostname_ip=0; client_username=0; http_reply_code=0; client_http_method=0; client_http_uri=0; web_hostname_ip=0; client_http_useragent=0; client_http_referer=0; client_http_cookie=0; server_remote_ip=0;

debug1 = 0
debug2 = 0
dict = {}
jobs = []
#syslog = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # tcp
syslog = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # udp

####################################################################################################

argtext='==================================================\nETPLC (Emerging Threats Proxy Logs Checker)\nCheck your Proxy or WebServer Logs with Emerging Threats Community Ruleset.\nhttp://etplc.org - Twitter: @Rmkml\n\nExample: tail -f /var/log/messages | etplc.py -f abc.rules.gz\n=================================================='
parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter, description=argtext)
parser.add_argument("-f", help="Specify Emerging Threats file Community Ruleset")
parser.add_argument("-s", help="Enable syslog alerting", action="store_true")
parser.add_argument("-c", help="Specify category like all|proxy|webserver")
parser.add_argument("-d", help="Enable output verbosity", action="store_true")
args = parser.parse_args()
if args.d:
 debug1 = 1
 debug2 = 1
if args.f is None: parser.error("Need a Emerging Threats file Community Ruleset\n\n"+argtext)
if args.f: argsfgz = re.search( r'\.gz$', args.f )
if args.c == "all": category = '(?:\$HTTP_SERVERS|\$HOME_NET|\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'
elif args.c == "proxy": category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'
elif args.c == "webserver": category = '(?:\$HTTP_SERVERS|\$HOME_NET)'
elif args.c: parser.error("Wrong Category\n\n"+argtext)
else: category = '\S+'
if args.s:
 syslogip='127.0.0.1'
 syslogport=514
 syslog.connect((syslogip,syslogport))
 socketgethostname=socket.gethostname()
if argsfgz:
 fileemergingthreats = gzip.open( args.f, 'rb' )
else:
 fileemergingthreats = open( args.f, 'rb' )

####################################################################################################

urilen1='\s*urilen\:\s*\d*\s*\<?\s*\>?\s*\d+\;'
flowbits1='\s*flowbits\:.*?\;'
flow1='flow\:\s*(?:to_server|to_client|from_client|from_server)?(?:\s*\,)?(?:established)?(?:\s*\,\s*)?(?:to_server|to_client|from_client|from_server)?\;'
httpmethod='\s*content\:\"([gG][eE][tT]|[pP][oO][sS][tT]|[hH][eE][aA][dD]|[sS][eE][aA][rR][cC][hH]|[pP][rR][oO][pP][fF][iI][nN][dD]|[tT][rR][aA][cC][eE]|[oO][pP][tT][iI][oO][nN][sS]|[dD][eE][bB][uU][gG]|[cC][oO][nN][nN][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[pP][uU][tT])\s*[^\"]*?\"\;(?:\s*(nocase)\;\s*|\s*http_method\;\s*|\s*depth\:\d+\;\s*)*'
contentoptions1='\s*(fast_pattern)(?:\:only|\:\d+\,\d+)?\;|\s*(nocase)\;|\s*offset\:\d+\;|\s*depth\:\d+\;|\s*distance\:\s*\-?(\d+)\;|\s*within\:(\d+)\;|\s*http_raw_uri\;'
negateuricontent1='\s*(?:uri)?content\:\!\"[^\"]*?\"\s*\;(?:\s*fast_pattern(?:\:only|\d+\,\d+)?\;|\s*nocase\;|\s*http_uri\;|\s*http_header\;|\s*http_cookie\;|\s*offset\:\d+\;|\s*depth\:\d+\;|\s*http_raw_uri\;|\s*distance\:\s*\-?\d+\;|\s*within\:\d+\;|\s*http_client_body\;)*'
extracontentoptions='\s*threshold\:.*?\;|\s*flowbits\:.*?\;|\s*isdataat\:\d+(?:\,relative)?\;|\s*dsize\:[\<\>]*\d+\;|\s*urilen\:\s*\d*\s*\<?\s*\>?\s*\d+\;|\s*detection_filter\:.*?\;|\s*priority\:\d+\;|\s*metadata\:.*?\;'
referencesidrev='(?:\s*reference\:.*?\;\s*)*\s*classtype\:.*?\;\s*sid\:\d+\;\s*rev\:\d+\;\s*\)\s*'
pcreuri='\s*pcre\:\"\/(.*?)\/[smiUGDIR]*\"\;' # not header/Cookie/Post_payload!
pcreagent='\s*pcre\:\"\/(.*?)\/[smiH]*\"\;'
pcrecookie='\s*pcre\:\"\/(.*?)\/[smiC]*\"\;'

match_http_uri1 = re.compile( r'^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+'+category+'\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:'+flow1+')?(?:'+flowbits1+')?(?:'+urilen1+')?(?:'+httpmethod+')?(?:'+urilen1+')?(?:'+negateuricontent1+')?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*\s*(?:http_uri|http_raw_uri)\;(?:'+contentoptions1+')*(?:'+negateuricontent1+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*(?:\s*http_uri\;)?(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*(?:\s*http_uri\;)?(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:'+extracontentoptions+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*(?:\s*http_uri\;)?(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:'+extracontentoptions+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*(?:\s*http_uri\;)?(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:'+extracontentoptions+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*(?:\s*http_uri\;)?(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:'+extracontentoptions+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*(?:\s*http_uri\;)?(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:'+extracontentoptions+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*(?:\s*http_uri\;)?(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:'+extracontentoptions+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*(?:\s*http_uri\;)?(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:'+extracontentoptions+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*(?:\s*http_uri\;)?(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:'+extracontentoptions+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*(?:\s*http_uri\;)?(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:'+extracontentoptions+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*(?:\s*http_uri\;)?(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:'+extracontentoptions+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*(?:\s*http_uri\;)?(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:'+extracontentoptions+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*\s*http_header\;(?:'+contentoptions1+')*(?:'+negateuricontent1+')?)?(?:'+pcreuri+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*\s*http_header\;(?:'+contentoptions1+')*(?:'+negateuricontent1+')?)?(?:'+pcreagent+')?(?:'+negateuricontent1+')?(?:'+extracontentoptions+')?'+referencesidrev+'$')
match_uricontent1 = re.compile( r'^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+'+category+'\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:'+flow1+')?(?:'+urilen1+')?(?:'+httpmethod+')?(?:'+negateuricontent1+')?\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*(?:'+negateuricontent1+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*\s*http_header\;(?:'+contentoptions1+')*(?:'+negateuricontent1+')?)?(?:\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:\s*(?:uri)?content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*)?(?:'+negateuricontent1+')?(?:'+pcreuri+')?(?:'+extracontentoptions+')?'+referencesidrev+'$')
match_uriheader1 = re.compile( r'^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+'+category+'\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:'+flowbits1+')?(?:'+flow1+')?(?:'+httpmethod+')?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*\s*http_uri\;(?:'+contentoptions1+')*(?:'+negateuricontent1+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*\s*http_header\;(?:'+contentoptions1+')*(?:'+negateuricontent1+')?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*(?:\s*http_uri\;)?(?:'+contentoptions1+')*(?:'+negateuricontent1+')?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*\s*http_header\;(?:'+contentoptions1+')*(?:'+negateuricontent1+')?)?(?:'+pcreuri+')?(?:'+extracontentoptions+')?'+referencesidrev+'$')
match_http_header1 = re.compile( r'^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+'+category+'\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:'+flow1+')?(?:'+urilen1+')?(?:'+httpmethod+')?(?:'+negateuricontent1+')?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*\s*http_header\;(?:'+contentoptions1+')*(?:'+negateuricontent1+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*\s*http_uri\;(?:'+contentoptions1+')*(?:'+negateuricontent1+')?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*\s*http_header\;(?:'+contentoptions1+')*(?:'+negateuricontent1+')?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*\s*http_uri\;(?:'+contentoptions1+')*(?:'+negateuricontent1+')?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*\s*http_header\;(?:'+contentoptions1+')*(?:'+negateuricontent1+')?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')*\s*http_uri\;(?:'+contentoptions1+')*(?:'+negateuricontent1+')?)?(?:'+pcreuri+')?(?:'+pcreagent+')?(?:'+extracontentoptions+')?'+referencesidrev+'$')
match_http_cookie1 = re.compile( r'^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+'+category+'\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:'+flow1+')?(?:'+httpmethod+')?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')?\s*http_uri\;(?:'+contentoptions1+')?(?:'+negateuricontent1+')?)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:'+contentoptions1+')?\s*http_cookie\;(?:'+contentoptions1+')?(?:'+negateuricontent1+')?(?:'+extracontentoptions+')?(?:'+pcreuri+')?(?:'+pcrecookie+')?(?:'+extracontentoptions+')?'+referencesidrev+'$')
match_ip1 = re.compile( r'^\s*alert\s+ip\s+\S+\s+\S+\s+\-\>\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d+)?)\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;[^\n]*?'+referencesidrev+'$')

####################################################################################################

#squiddefault1 = re.compile( r'^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)\s(\S+)\s\S+\:\s(\d+\.\d+)\s+\d+\s+(\S+)\s+[A-Z\_]+\/(\d+)\s\d+\s+([A-Z]+)\s+(\S+)\s+\-\s+[A-Z]+\/(\S+)\s')
squiddefault1 = re.compile( r'^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)?(?:\s(\S+)\s\S+\:\s)?(\d+\.\d+)\s+\d+\s+(\S+)\s+[A-Z\_]+\/(\d+)\s\d+\s+([A-Z]+)\s+(\S+)\s+\-\s+[A-Z\_]+\/(\S+)\s')
#squidua1 = re.compile( r'^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)?(?:\s(\S+)\s\S+\:\s+)?\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+[A-Z\_]+\/(\d+)\s+\-\s+\[(.*?)\]\s+\d+\s+([^\s]+)\s([^\s]+)\s\-\s[^\/]+\/([^\s]+)\s[^\s]+\s\"([^\"]+)\" \"([^\"]+)\" \"([^\"]+)\"')
squidua1 = re.compile( r'^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)?(?:\s(\S+)\s\S+\:\s+)?\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+[A-Z\_]+\/(\d+)\s+\-\s+\[(.*?)\]\s+\d+\s+([^\s]+)\s([^\s]+)\s\-\s[^\/]+\/([^\s]+)\s[^\s]+\s\"([^\"]+)\" \"([^\"]+)\" \"([^\"]+)\"(?:\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?')
#apache1 = re.compile( r'^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)?(?:\s(\S+)\s\S+\:\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\-\s+\-\s+\[(.*?)\]\s+\"([^\s]+)\s([^\s]+)\s.*\"\s(\d+)\s(?:\d+|\-)(?:\s\"(.*?)\")?(?:\s\"(.*?)\")?(?:\s\"(.*?)\")?$')
apache1 = re.compile( r'^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)?(?:\s(\S+)\s\S+\:\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\-\s+(\S+)\s+\[([^\]]*?)\]\s+\"([^\s]+)\s(\S+)\s\S+\"\s(\d+)\s(?:\d+|\-)(?:\s\"(.*?)\")?(?:\s\"(.*?)\")?(?:\s\"(.*?)\")?')
tmg1 = re.compile( r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\t|\\t)+(\S+)(?:\t|\\t)+(.*?)(?:\t|\\t)+(\d{4}\-\d{2}\-\d{2})(?:\t|\\t)+(\d{2}\:\d{2}\:\d{2})(?:\t|\\t)+([0-9a-zA-Z\-\_]+)(?:\t|\\t)+(.*?)(?:\t|\\t)+(.*?)(?:\t|\\t)+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+.*?(?:\t|\\t)+([0-9a-zA-Z\-\_]+)(?:\t|\\t)+(.*?)(?:\t|\\t)+\S+(?:\t|\\t)+(\d+)')
bluecoat1c = re.compile( r'^(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(\S+)\s)?(?:\S+\:\s)?(\d{4}\-\d{2}\-\d{2})\s(\d{2}\:\d{2}\:\d{2})\s\d+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\S+)\s(?:\-|\S+)\s\"[^\"]*?\"\s\S+\s(\d+)\s(\S+)\s\S+\s\S+\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(?:\"([^\"]*?)\"|(\-))\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d+\s\d+\s\-\s?')
bluecoatmethod2c = re.compile( r'^(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(\S+)\s)?(?:\S+\:\s)?(\d{4}\-\d{2}\-\d{2})\s(\d{2}\:\d{2}\:\d{2})\s\d+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\S+)\s(?:\-|\S+)\s\"[^\"]*?\"\s\S+\s(\d+)\s(\S+)\s\S+\s\S+\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(?:\"([^\"]*?)\"|(\-))\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d+\s\d+\s\-\s?')
bluecoatmethod3c = re.compile( r'(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(\S+)\s)?(?:\S+\:\s)?(\d{4}\-\d{2}\-\d{2})\s(\d{2}\:\d{2}\:\d{2})\s\d+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\d+)\s\S+\s\d+\s\d+\s(\S+)\s(\S+)\s(\S+)\s(\d+)\s(\S+)\s(\S+)\s(\S+)\s\S+\s\S+\s\S+\s(\S+)\s(?:\"([^\"]*?)\"|(\-))\s\S+\s(?:\"(?:[^\"]*?)\"|(?:\-))\s(?:\"(?:[^\"]*?)\"|(?:\-))\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
mcafeewg1 = re.compile( r'^(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(\S+)\s)?(?:\S+\:\s)?\s*\[([^\]]*?)\] \"([^\"]*?)\" \"[^\"]*?\" (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (0|\d{3}) \"([^\s]+)\s([^\s]+)\s[^\"]*?\" \"[^\"]*?\" \"[^\"]*?\" \"[^\"]*?\" \d+ \"([^\"]*)\" \"[^\"]*?\" \S+ (?:\S+)?$')

####################################################################################################

def function_replacement_http_uri(match):
 abc = match.group() 
 abc = re.sub( r"\|", "", abc )
 abc = re.sub( r"\s*([0-9A-Fa-f]{2})\s*", r"\\x\1", abc )
 return abc

#######################################################################################

def function_replacement_http_agent_short(match):
 if sys.version_info>=(3,):
  match = match.group(1)
  return bytes.fromhex(match).decode('utf-8')
 else:
  return match.group(1).decode("hex")

#######################################################################################

def function_match_http_uri( lineet ):
 if debug1: print("brut1: "+lineet)
 etmsg1 = match_http_uri2.group(1)
 http_method2 = 0
 http_methodnocase3 = 0
 http_method2 = match_http_uri2.group(2)
 http_methodnocase3 = match_http_uri2.group(3)
 http_uri03 = match_http_uri2.group(4)
 http_urifast5 = match_http_uri2.group(5)
 http_urinocase5 = match_http_uri2.group(6)
 http_urifast9 = match_http_uri2.group(9)
 http_urinocase10 = match_http_uri2.group(10)
 http_uri08 = match_http_uri2.group(13)
 http_urifast14 = match_http_uri2.group(14)
 http_urinocase12 = match_http_uri2.group(15)
 distance9 = match_http_uri2.group(16)
 distance10 = match_http_uri2.group(17)
 http_urifast18 = match_http_uri2.group(18)
 http_urinocase15 = match_http_uri2.group(19)
 distance11 = match_http_uri2.group(20)
 distance12 = match_http_uri2.group(21)
 http_uri13 = match_http_uri2.group(22)
 http_urifast23 = match_http_uri2.group(23)
 http_urinocase19 = match_http_uri2.group(24)
 distance14 = match_http_uri2.group(25)
 distance15 = match_http_uri2.group(26)
 http_urifast27 = match_http_uri2.group(27)
 http_urinocase22 = match_http_uri2.group(28)
 distance16 = match_http_uri2.group(29)
 distance17 = match_http_uri2.group(30)
 http_uri18 = match_http_uri2.group(31)
 http_urifast32 = match_http_uri2.group(32)
 http_urinocase26 = match_http_uri2.group(33)
 distance19 = match_http_uri2.group(34)
 distance20 = match_http_uri2.group(35)
 http_urifast36 = match_http_uri2.group(36)
 http_urinocase29 = match_http_uri2.group(37)
 distance21 = match_http_uri2.group(38)
 distance22 = match_http_uri2.group(39)
 http_uri23 = match_http_uri2.group(40)
 http_urifast41 = match_http_uri2.group(41)
 http_urinocase33 = match_http_uri2.group(42)
 distance24 = match_http_uri2.group(43)
 distance25 = match_http_uri2.group(44)
 http_urifast44 = match_http_uri2.group(45)
 http_urinocase36 = match_http_uri2.group(46)
 distance26 = match_http_uri2.group(47)
 distance27 = match_http_uri2.group(48)
 http_uri28 = match_http_uri2.group(49)
 http_urifast49 = match_http_uri2.group(50)
 http_urinocase40 = match_http_uri2.group(51)
 distance29 = match_http_uri2.group(52)
 distance30 = match_http_uri2.group(53)
 http_urifast54 = match_http_uri2.group(54)
 http_urinocase43 = match_http_uri2.group(55)
 distance31 = match_http_uri2.group(56)
 distance32 = match_http_uri2.group(57)
 http_uri33 = match_http_uri2.group(58)
 http_urifast58 = match_http_uri2.group(59)
 http_urinocase47 = match_http_uri2.group(60)
 distance34 = match_http_uri2.group(61)
 distance35 = match_http_uri2.group(62)
 http_urifast62 = match_http_uri2.group(63)
 http_urinocase50 = match_http_uri2.group(64)
 distance36 = match_http_uri2.group(65)
 distance37 = match_http_uri2.group(66)
 http_uri38 = match_http_uri2.group(67)
 http_urinocase54 = match_http_uri2.group(68)
 http_urinocase57 = match_http_uri2.group(57)
 http_uri43 = match_http_uri2.group(60)
 http_urinocase61 = match_http_uri2.group(61)
 http_urinocase64 = match_http_uri2.group(64)
 http_uri48 = match_http_uri2.group(67)
 http_urinocase68 = match_http_uri2.group(68)
 http_urinocase71 = match_http_uri2.group(71)
 http_uri53 = match_http_uri2.group(74)
 http_urinocase75 = match_http_uri2.group(75)
 http_urinocase78 = match_http_uri2.group(78)
 http_uri58 = match_http_uri2.group(81)
 http_urinocase82 = match_http_uri2.group(82)
 http_urinocase85 = match_http_uri2.group(85)
 http_uri63 = match_http_uri2.group(88)
 http_urinocase89 = match_http_uri2.group(89)
 http_urinocase92 = match_http_uri2.group(92)
 http_header68 = match_http_uri2.group(95)
 http_headernocase96 = match_http_uri2.group(96)
 http_headernocase99 = match_http_uri2.group(99)
 http_header121 = match_http_uri2.group(121)
 http_headerfast122 = match_http_uri2.group(122)
 http_headernocase123 = match_http_uri2.group(123)
 distance124 = match_http_uri2.group(124)
 distance125 = match_http_uri2.group(125)
 http_headerfast126 = match_http_uri2.group(126)
 http_headernocase127 = match_http_uri2.group(127)
 distance128 = match_http_uri2.group(128)
 distance129 = match_http_uri2.group(129)
 pcre_uri73 = match_http_uri2.group(130)
 http_header74 = match_http_uri2.group(131)
 http_headerfast132 = match_http_uri2.group(132)
 http_headernocase104 = match_http_uri2.group(133)
 distance75 = match_http_uri2.group(134)
 distance76 = match_http_uri2.group(135)
 http_headerfast136 = match_http_uri2.group(136)
 http_headernocase107 = match_http_uri2.group(137)
 distance77 = match_http_uri2.group(138)
 distance78 = match_http_uri2.group(139)
 pcre_agent79 = match_http_uri2.group(140)

 # check what is http_uri best length ?
 httpuricourt=0
 http_uri03_length=0
 http_uri08_length=0
 http_uri13_length=0
 http_uri18_length=0
 http_uri23_length=0
 http_uri28_length=0
 http_uri33_length=0
 http_uri38_length=0
 http_uri43_length=0
 http_uri48_length=0
 http_uri53_length=0
 http_uri58_length=0
 http_uri63_length=0
 if http_uri03: http_uri03_length=http_uri03.__len__()
 if http_uri08: http_uri08_length=http_uri08.__len__()
 if http_uri13: http_uri13_length=http_uri13.__len__()
 if http_uri18: http_uri18_length=http_uri18.__len__()
 if http_uri23: http_uri23_length=http_uri23.__len__()
 if http_uri28: http_uri28_length=http_uri28.__len__()
 if http_uri33: http_uri33_length=http_uri33.__len__()
 if http_uri38: http_uri38_length=http_uri38.__len__()
 if http_uri43: http_uri43_length=http_uri43.__len__()
 if http_uri48: http_uri48_length=http_uri48.__len__()
 if http_uri53: http_uri53_length=http_uri53.__len__()
 if http_uri58: http_uri58_length=http_uri58.__len__()
 if http_uri63: http_uri63_length=http_uri63.__len__()
 if http_uri03_length >= http_uri08_length and http_uri03_length >= http_uri13_length and http_uri03_length >= http_uri18_length and http_uri03_length >= http_uri23_length and http_uri03_length >= http_uri28_length and http_uri03_length >= http_uri33_length and http_uri03_length >= http_uri38_length and http_uri03_length >= http_uri43_length and http_uri03_length >= http_uri48_length and http_uri03_length >= http_uri53_length and http_uri03_length >= http_uri58_length and http_uri03_length >= http_uri63_length :
  httpuricourt=http_uri03
 elif http_uri08_length >= http_uri03_length and http_uri08_length >= http_uri13_length and http_uri08_length >= http_uri18_length and http_uri08_length >= http_uri23_length and http_uri08_length >= http_uri28_length and http_uri08_length >= http_uri33_length and http_uri08_length >= http_uri38_length and http_uri08_length >= http_uri43_length and http_uri08_length >= http_uri48_length and http_uri08_length >= http_uri53_length and http_uri08_length >= http_uri58_length and http_uri08_length >= http_uri63_length :
  httpuricourt=http_uri08
 elif http_uri13_length >= http_uri03_length and http_uri13_length >= http_uri08_length and http_uri13_length >= http_uri18_length and http_uri13_length >= http_uri23_length and http_uri13_length >= http_uri28_length and http_uri13_length >= http_uri33_length and http_uri13_length >= http_uri38_length and http_uri13_length >= http_uri43_length and http_uri13_length >= http_uri48_length and http_uri13_length >= http_uri53_length and http_uri13_length >= http_uri58_length and http_uri13_length >= http_uri63_length :
  httpuricourt=http_uri13
 elif http_uri18_length >= http_uri03_length and http_uri18_length >= http_uri08_length and http_uri18_length >= http_uri13_length and http_uri18_length >= http_uri23_length and http_uri18_length >= http_uri28_length and http_uri18_length >= http_uri33_length and http_uri18_length >= http_uri38_length and http_uri18_length >= http_uri43_length and http_uri18_length >= http_uri48_length and http_uri18_length >= http_uri53_length and http_uri18_length >= http_uri58_length and http_uri18_length >= http_uri63_length :
  httpuricourt=http_uri18
 elif http_uri23_length >= http_uri03_length and http_uri23_length >= http_uri08_length and http_uri23_length >= http_uri13_length and http_uri23_length >= http_uri18_length and http_uri23_length >= http_uri28_length and http_uri23_length >= http_uri33_length and http_uri23_length >= http_uri38_length and http_uri23_length >= http_uri43_length and http_uri23_length >= http_uri48_length and http_uri23_length >= http_uri53_length and http_uri23_length >= http_uri58_length and http_uri23_length >= http_uri63_length :
  httpuricourt=http_uri23
 elif http_uri28_length >= http_uri03_length and http_uri28_length >= http_uri08_length and http_uri28_length >= http_uri13_length and http_uri28_length >= http_uri18_length and http_uri28_length >= http_uri23_length and http_uri28_length >= http_uri33_length and http_uri28_length >= http_uri38_length and http_uri28_length >= http_uri43_length and http_uri28_length >= http_uri48_length and http_uri28_length >= http_uri53_length and http_uri28_length >= http_uri58_length and http_uri28_length >= http_uri63_length :
  httpuricourt=http_uri28
 elif http_uri33_length >= http_uri03_length and http_uri33_length >= http_uri08_length and http_uri33_length >= http_uri13_length and http_uri33_length >= http_uri18_length and http_uri33_length >= http_uri23_length and http_uri33_length >= http_uri28_length and http_uri33_length >= http_uri38_length and http_uri33_length >= http_uri43_length and http_uri33_length >= http_uri48_length and http_uri33_length >= http_uri53_length and http_uri33_length >= http_uri58_length and http_uri33_length >= http_uri63_length :
  httpuricourt=http_uri33
 elif http_uri38_length >= http_uri03_length and http_uri38_length >= http_uri08_length and http_uri38_length >= http_uri13_length and http_uri38_length >= http_uri18_length and http_uri38_length >= http_uri23_length and http_uri38_length >= http_uri28_length and http_uri38_length >= http_uri33_length and http_uri38_length >= http_uri43_length and http_uri38_length >= http_uri48_length and http_uri38_length >= http_uri53_length and http_uri38_length >= http_uri58_length and http_uri38_length >= http_uri63_length :
  httpuricourt=http_uri38
 elif http_uri43_length >= http_uri03_length and http_uri43_length >= http_uri08_length and http_uri43_length >= http_uri13_length and http_uri43_length >= http_uri18_length and http_uri43_length >= http_uri23_length and http_uri43_length >= http_uri28_length and http_uri43_length >= http_uri33_length and http_uri43_length >= http_uri38_length and http_uri43_length >= http_uri48_length and http_uri43_length >= http_uri53_length and http_uri43_length >= http_uri58_length and http_uri43_length >= http_uri63_length :
  httpuricourt=http_uri43
 elif http_uri48_length >= http_uri03_length and http_uri48_length >= http_uri08_length and http_uri48_length >= http_uri13_length and http_uri48_length >= http_uri18_length and http_uri48_length >= http_uri23_length and http_uri48_length >= http_uri28_length and http_uri48_length >= http_uri33_length and http_uri48_length >= http_uri38_length and http_uri48_length >= http_uri43_length and http_uri48_length >= http_uri53_length and http_uri48_length >= http_uri58_length and http_uri48_length >= http_uri63_length :
  httpuricourt=http_uri48
 elif http_uri53_length >= http_uri03_length and http_uri53_length >= http_uri08_length and http_uri53_length >= http_uri13_length and http_uri53_length >= http_uri18_length and http_uri53_length >= http_uri23_length and http_uri53_length >= http_uri28_length and http_uri53_length >= http_uri33_length and http_uri53_length >= http_uri38_length and http_uri53_length >= http_uri43_length and http_uri53_length >= http_uri48_length and http_uri53_length >= http_uri58_length and http_uri53_length >= http_uri63_length :
  httpuricourt=http_uri53
 elif http_uri58_length >= http_uri03_length and http_uri58_length >= http_uri08_length and http_uri58_length >= http_uri13_length and http_uri58_length >= http_uri18_length and http_uri58_length >= http_uri23_length and http_uri58_length >= http_uri28_length and http_uri58_length >= http_uri33_length and http_uri58_length >= http_uri38_length and http_uri58_length >= http_uri43_length and http_uri58_length >= http_uri48_length and http_uri58_length >= http_uri53_length and http_uri58_length >= http_uri63_length :
  httpuricourt=http_uri58
 elif http_uri63_length >= http_uri03_length and http_uri63_length >= http_uri08_length and http_uri63_length >= http_uri13_length and http_uri63_length >= http_uri18_length and http_uri63_length >= http_uri23_length and http_uri63_length >= http_uri28_length and http_uri63_length >= http_uri33_length and http_uri63_length >= http_uri38_length and http_uri63_length >= http_uri43_length and http_uri63_length >= http_uri48_length and http_uri63_length >= http_uri53_length and http_uri63_length >= http_uri58_length :
  httpuricourt=http_uri63

 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri03 ) # (
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri03 ) # )
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri03 ) # *
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri03 ) # +
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri03 ) # -
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri03 ) # .
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri03 ) # /
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri03 ) # ?
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri03 ) # [
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri03 ) # ]
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri03 ) # ^
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri03 ) # {
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri03 ) # }
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri08 ) # (
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri08 ) # )
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri08 ) # *
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri08 ) # +
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri08 ) # -
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri08 ) # .
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri08 ) # /
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri08 ) # ?
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri08 ) # [
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri08 ) # ]
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri08 ) # ^
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri08 ) # {
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri08 ) # }
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri13 ) # (
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri13 ) # )
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri13 ) # *
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri13 ) # +
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri13 ) # -
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri13 ) # .
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri13 ) # /
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri13 ) # ?
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri13 ) # [
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri13 ) # ]
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri13 ) # ^
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri13 ) # {
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri13 ) # }
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri18 ) # (
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri18 ) # )
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri18 ) # *
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri18 ) # +
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri18 ) # -
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri18 ) # .
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri18 ) # /
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri18 ) # ?
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri18 ) # [
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri18 ) # ]
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri18 ) # ^
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri18 ) # {
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri18 ) # }
 if http_uri23: http_uri23 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri23 ) # (
 if http_uri23: http_uri23 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri23 ) # )
 if http_uri23: http_uri23 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri23 ) # *
 if http_uri23: http_uri23 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri23 ) # +
 if http_uri23: http_uri23 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri23 ) # -
 if http_uri23: http_uri23 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri23 ) # .
 if http_uri23: http_uri23 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri23 ) # /
 if http_uri23: http_uri23 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri23 ) # ?
 if http_uri23: http_uri23 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri23 ) # [
 if http_uri23: http_uri23 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri23 ) # ]
 if http_uri23: http_uri23 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri23 ) # ^
 if http_uri23: http_uri23 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri23 ) # {
 if http_uri23: http_uri23 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri23 ) # }
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri28 ) # (
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri28 ) # )
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri28 ) # *
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri28 ) # +
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri28 ) # -
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri28 ) # .
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri28 ) # /
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri28 ) # ?
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri28 ) # [
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri28 ) # ]
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri28 ) # ^
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri28 ) # {
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri28 ) # }
 if http_uri33: http_uri33 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri33 ) # (
 if http_uri33: http_uri33 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri33 ) # )
 if http_uri33: http_uri33 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri33 ) # *
 if http_uri33: http_uri33 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri33 ) # +
 if http_uri33: http_uri33 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri33 ) # -
 if http_uri33: http_uri33 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri33 ) # .
 if http_uri33: http_uri33 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri33 ) # /
 if http_uri33: http_uri33 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri33 ) # ?
 if http_uri33: http_uri33 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri33 ) # [
 if http_uri33: http_uri33 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri33 ) # ]
 if http_uri33: http_uri33 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri33 ) # ^
 if http_uri33: http_uri33 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri33 ) # {
 if http_uri33: http_uri33 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri33 ) # }
 if http_uri38: http_uri38 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri38 ) # (
 if http_uri38: http_uri38 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri38 ) # )
 if http_uri38: http_uri38 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri38 ) # *
 if http_uri38: http_uri38 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri38 ) # +
 if http_uri38: http_uri38 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri38 ) # -
 if http_uri38: http_uri38 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri38 ) # .
 if http_uri38: http_uri38 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri38 ) # /
 if http_uri38: http_uri38 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri38 ) # ?
 if http_uri38: http_uri38 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri38 ) # [
 if http_uri38: http_uri38 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri38 ) # ]
 if http_uri38: http_uri38 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri38 ) # ^
 if http_uri38: http_uri38 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri38 ) # {
 if http_uri38: http_uri38 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri38 ) # }
 if http_uri43: http_uri43 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri43 ) # (
 if http_uri43: http_uri43 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri43 ) # )
 if http_uri43: http_uri43 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri43 ) # *
 if http_uri43: http_uri43 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri43 ) # +
 if http_uri43: http_uri43 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri43 ) # -
 if http_uri43: http_uri43 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri43 ) # .
 if http_uri43: http_uri43 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri43 ) # /
 if http_uri43: http_uri43 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri43 ) # ?
 if http_uri43: http_uri43 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri43 ) # [
 if http_uri43: http_uri43 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri43 ) # ]
 if http_uri43: http_uri43 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri43 ) # ^
 if http_uri43: http_uri43 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri43 ) # {
 if http_uri43: http_uri43 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri43 ) # }
 if http_uri48: http_uri48 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri48 ) # (
 if http_uri48: http_uri48 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri48 ) # )
 if http_uri48: http_uri48 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri48 ) # *
 if http_uri48: http_uri48 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri48 ) # +
 if http_uri48: http_uri48 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri48 ) # -
 if http_uri48: http_uri48 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri48 ) # .
 if http_uri48: http_uri48 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri48 ) # /
 if http_uri48: http_uri48 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri48 ) # ?
 if http_uri48: http_uri48 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri48 ) # [
 if http_uri48: http_uri48 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri48 ) # ]
 if http_uri48: http_uri48 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri48 ) # ^
 if http_uri48: http_uri48 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri48 ) # {
 if http_uri48: http_uri48 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri48 ) # }
 if http_uri53: http_uri53 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri53 ) # (
 if http_uri53: http_uri53 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri53 ) # )
 if http_uri53: http_uri53 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri53 ) # *
 if http_uri53: http_uri53 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri53 ) # +
 if http_uri53: http_uri53 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri53 ) # -
 if http_uri53: http_uri53 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri53 ) # .
 if http_uri53: http_uri53 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri53 ) # /
 if http_uri53: http_uri53 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri53 ) # ?
 if http_uri53: http_uri53 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri53 ) # [
 if http_uri53: http_uri53 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri53 ) # ]
 if http_uri53: http_uri53 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri53 ) # ^
 if http_uri53: http_uri53 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri53 ) # {
 if http_uri53: http_uri53 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri53 ) # }
 if http_uri58: http_uri58 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri58 ) # (
 if http_uri58: http_uri58 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri58 ) # )
 if http_uri58: http_uri58 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri58 ) # *
 if http_uri58: http_uri58 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri58 ) # +
 if http_uri58: http_uri58 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri58 ) # -
 if http_uri58: http_uri58 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri58 ) # .
 if http_uri58: http_uri58 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri58 ) # /
 if http_uri58: http_uri58 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri58 ) # ?
 if http_uri58: http_uri58 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri58 ) # [
 if http_uri58: http_uri58 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri58 ) # ]
 if http_uri58: http_uri58 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri58 ) # ^
 if http_uri58: http_uri58 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri58 ) # {
 if http_uri58: http_uri58 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri58 ) # }
 if http_uri63: http_uri63 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri63 ) # (
 if http_uri63: http_uri63 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri63 ) # )
 if http_uri63: http_uri63 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri63 ) # *
 if http_uri63: http_uri63 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri63 ) # +
 if http_uri63: http_uri63 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri63 ) # -
 if http_uri63: http_uri63 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri63 ) # .
 if http_uri63: http_uri63 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri63 ) # /
 if http_uri63: http_uri63 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri63 ) # ?
 if http_uri63: http_uri63 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri63 ) # [
 if http_uri63: http_uri63 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri63 ) # ]
 if http_uri63: http_uri63 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri63 ) # ^
 if http_uri63: http_uri63 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri63 ) # {
 if http_uri63: http_uri63 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri63 ) # }
 if http_header68: http_header68 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_header68 ) # (
 if http_header68: http_header68 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_header68 ) # )
 if http_header68: http_header68 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_header68 ) # *
 if http_header68: http_header68 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_header68 ) # +
 if http_header68: http_header68 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_header68 ) # -
 if http_header68: http_header68 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_header68 ) # .
 if http_header68: http_header68 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_header68 ) # /
 if http_header68: http_header68 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_header68 ) # ?
 if http_header68: http_header68 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_header68 ) # [
 if http_header68: http_header68 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_header68 ) # ]
 #if http_header68: http_header68 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_header68 ) # ^
 if http_header68: http_header68 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_header68 ) # {
 if http_header68: http_header68 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_header68 ) # }
 if http_header121: http_header121 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_header121 ) # (
 if http_header121: http_header121 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_header121 ) # )
 if http_header121: http_header121 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_header121 ) # *
 if http_header121: http_header121 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_header121 ) # +
 if http_header121: http_header121 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_header121 ) # -
 if http_header121: http_header121 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_header121 ) # .
 if http_header121: http_header121 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_header121 ) # /
 if http_header121: http_header121 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_header121 ) # ?
 if http_header121: http_header121 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_header121 ) # [
 if http_header121: http_header121 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_header121 ) # ]
 #if http_header121: http_header121 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_header121 ) # ^
 if http_header121: http_header121 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_header121 ) # {
 if http_header121: http_header121 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_header121 ) # }
 #if pcre_uri73: pcre_uri73 = re.sub( r'(?<!\x5C)\x24', '', pcre_uri73 ) # $
 if http_header74: http_header74 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_header74 ) # (
 if http_header74: http_header74 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_header74 ) # )
 if http_header74: http_header74 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_header74 ) # *
 if http_header74: http_header74 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_header74 ) # +
 if http_header74: http_header74 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_header74 ) # -
 if http_header74: http_header74 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_header74 ) # .
 if http_header74: http_header74 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_header74 ) # /
 if http_header74: http_header74 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_header74 ) # ?
 if http_header74: http_header74 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_header74 ) # [
 if http_header74: http_header74 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_header74 ) # ]
 #if http_header74: http_header74 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_header74 ) # ^
 if http_header74: http_header74 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_header74 ) # {
 if http_header74: http_header74 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_header74 ) # }
 #if pcre_uri79: pcre_uri79 = re.sub( r'(?<!\x5C)\x24', '', pcre_uri79 ) # $

 if http_uri03: http_uri03 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri03)
 if http_uri08: http_uri08 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri08)
 if http_uri13: http_uri13 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri13)
 if http_uri18: http_uri18 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri18)
 if http_uri23: http_uri23 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri23)
 if http_uri28: http_uri28 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri28)
 if http_uri33: http_uri33 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri33)
 if http_uri38: http_uri38 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri38)
 if http_uri43: http_uri43 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri43)
 if http_uri48: http_uri48 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri48)
 if http_uri53: http_uri53 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri53)
 if http_uri58: http_uri58 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri58)
 if http_uri63: http_uri63 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri63)
 if http_header68: http_header68 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_header68)
 if http_header121: http_header121 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_header121)
 # ne pas faire d'echappement sur la pcre ($pcre_uri73)
 if http_header74: http_header74 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_header74)
 # ne pas faire d'echappement sur la pcre ($pcre_agent79)

 abc1=0
 httppcreagent=0
 httpagentshort=0
 httpreferer=0
 pcrereferer=0
 tableauuri1=0
 tableauuridistance1=()
 tableauuridistance2=()

 if pcre_uri73 and http_uri03 and ( http_uri03.lower() in pcre_uri73.lower() ):
  http_uri03=""
  if debug1: print("ok trouvé grep3a ("+http_uri03+")")
 elif pcre_uri73 and http_uri03 and ( '&' in http_uri03 ):
  http_uri03 = re.sub( r'\&', r'\\x26', http_uri03 )
  if http_uri03.lower() in pcre_uri73.lower():
   http_uri03=""
   if debug1: print("ok trouvé grep3b ("+http_uri03+")")
 elif pcre_uri73 and http_uri03 and ( '=' in http_uri03 ):
  http_uri03 = re.sub( r'\=', r'\\x3D', http_uri03 )
  if http_uri03.lower() in pcre_uri73.lower():
   http_uri03=""
   if debug1: print("ok trouvé grep3c ("+http_uri03+")")
 if pcre_uri73 and http_uri08 and ( http_uri08.lower() in pcre_uri73.lower() ):
  http_uri08=""
  if debug1: print("ok trouvé grep8a ("+http_uri08+")")
 elif pcre_uri73 and http_uri08 and ( '&' in http_uri08 ):
  http_uri08 = re.sub( r'\&', r'\\x26', http_uri08 )
  if http_uri08.lower() in pcre_uri73.lower():
   http_uri08=""
   if debug1: print("ok trouvé grep8b ("+http_uri08+")")
 elif pcre_uri73 and http_uri08 and ( '=' in http_uri08 ):
  http_uri08 = re.sub( r'\=', r'\\x3D', http_uri08 )
  if http_uri08.lower() in pcre_uri73.lower():
   http_uri08=""
   if debug1: print("ok trouvé grep8c ("+http_uri08+")")
 if pcre_uri73 and http_uri13 and ( http_uri13.lower() in pcre_uri73.lower() ):
  http_uri13=""
  if debug1: print("ok trouvé grep13a ("+http_uri13+")")
 elif pcre_uri73 and http_uri13 and ( '&' in http_uri13 ):
  http_uri13 = re.sub( r'\&', r'\\x26', http_uri13 )
  if http_uri13.lower() in pcre_uri73.lower():
   http_uri13=""
   if debug1: print("ok trouvé grep13b ("+http_uri13+")")
 elif pcre_uri73 and http_uri13 and ( '=' in http_uri13 ):
  http_uri13 = re.sub( r'\=', r'\\x3D', http_uri13 )
  if http_uri13.lower() in pcre_uri73.lower():
   http_uri13=""
   if debug1: print("ok trouvé grep13c ("+http_uri13+")")
 if pcre_uri73 and http_uri18 and ( http_uri18.lower() in pcre_uri73.lower() ):
  http_uri18=""
  if debug1: print("ok trouvé grep18a ("+http_uri18+")")
 elif pcre_uri73 and http_uri18 and ( '&' in http_uri18 ):
  http_uri18 = re.sub( r'\&', r'\\x26', http_uri18 )
  if http_uri18.lower() in pcre_uri73.lower():
   http_uri18=""
   if debug1: print("ok trouvé grep18b ("+http_uri18+")")
 elif pcre_uri73 and http_uri18 and ( '=' in http_uri18 ):
  http_uri18 = re.sub( r'\=', r'\\x3D', http_uri18 )
  if http_uri18.lower() in pcre_uri73.lower():
   http_uri18=""
   if debug1: print("ok trouvé grep18c ("+http_uri18+")")
 if pcre_uri73 and http_uri23 and ( http_uri23.lower() in pcre_uri73.lower() ):
  http_uri23=""
  if debug1: print("ok trouvé grep23a ("+http_uri23+")")
 elif pcre_uri73 and http_uri23 and ( '&' in http_uri23 ):
  http_uri23 = re.sub( r'\&', r'\\x26', http_uri23 )
  if http_uri23.lower() in pcre_uri73.lower():
   http_uri23=""
   if debug1: print("ok trouvé grep23b ("+http_uri23+")")
 elif pcre_uri73 and http_uri23 and ( '=' in http_uri23 ):
  http_uri23 = re.sub( r'\=', r'\\x3D', http_uri23 )
  if http_uri23.lower() in pcre_uri73.lower():
   http_uri23=""
   if debug1: print("ok trouvé grep23c ("+http_uri23+")")
 if pcre_uri73 and http_uri28 and ( http_uri28.lower() in pcre_uri73.lower() ):
  http_uri28=""
  if debug1: print("ok trouvé grep28a ("+http_uri23+")")
 elif pcre_uri73 and http_uri28 and ( '&' in http_uri28 ):
  http_uri28 = re.sub( r'\&', r'\\x26', http_uri28 )
  if http_uri28.lower() in pcre_uri73.lower():
   http_uri28=""
   if debug1: print("ok trouvé grep28b ("+http_uri28+")")
 elif pcre_uri73 and http_uri28 and ( '=' in http_uri28 ):
  http_uri28 = re.sub( r'\=', r'\\x3D', http_uri28 )
  if http_uri28.lower() in pcre_uri73.lower():
   http_uri28=""
   if debug1: print("ok trouvé grep28c ("+http_uri28+")")
 if pcre_uri73 and http_uri33 and ( http_uri33.lower() in pcre_uri73.lower() ):
  http_uri33=""
  if debug1: print("ok trouvé grep33a ("+http_uri33+")")
 elif pcre_uri73 and http_uri33 and ( '&' in http_uri33 ):
  http_uri33 = re.sub( r'\&', r'\\x26', http_uri33 )
  if http_uri33.lower() in pcre_uri73.lower():
   http_uri33=""
   if debug1: print("ok trouvé grep33b ("+http_uri33+")")
 elif pcre_uri73 and http_uri33 and ( '=' in http_uri33 ):
  http_uri33 = re.sub( r'\=', r'\\x3D', http_uri33 )
  if http_uri33.lower() in pcre_uri73.lower():
   http_uri33=""
   if debug1: print("ok trouvé grep33c ("+http_uri33+")")
 if pcre_uri73 and http_uri38 and ( http_uri38.lower() in pcre_uri73.lower() ):
  http_uri38=""
  if debug1: print("ok trouvé grep38a ("+http_uri38+")")
 elif pcre_uri73 and http_uri38 and ( '&' in http_uri38 ):
  http_uri38 = re.sub( r'\&', r'\\x26', http_uri38 )
  if http_uri38.lower() in pcre_uri73.lower():
   http_uri38=""
   if debug1: print("ok trouvé grep38b ("+http_uri38+")")
 elif pcre_uri73 and http_uri38 and ( '=' in http_uri38 ):
  http_uri38 = re.sub( r'\=', r'\\x3D', http_uri38 )
  if http_uri38.lower() in pcre_uri73.lower():
   http_uri38=""
   if debug1: print("ok trouvé grep38c ("+http_uri38+")")
 if pcre_uri73 and http_uri43 and ( http_uri43.lower() in pcre_uri73.lower() ):
  http_uri43=""
  if debug1: print("ok trouvé grep43a ("+http_uri43+")")
 elif pcre_uri73 and http_uri43 and ( '&' in http_uri43 ):
  http_uri43 = re.sub( r'\&', r'\\x26', http_uri43 )
  if http_uri43.lower() in pcre_uri73.lower():
   http_uri43=""
   if debug1: print("ok trouvé grep43b ("+http_uri43+")")
 elif pcre_uri73 and http_uri43 and ( '=' in http_uri43 ):
  http_uri43 = re.sub( r'\=', r'\\x3D', http_uri43 )
  if http_uri43.lower() in pcre_uri73.lower():
   http_uri43=""
   if debug1: print("ok trouvé grep43c ("+http_uri43+")")
 if pcre_uri73 and http_uri48 and ( http_uri48.lower() in pcre_uri73.lower() ):
  http_uri48=""
  if debug1: print("ok trouvé grep48a ("+http_uri43+")")
 elif pcre_uri73 and http_uri48 and ( '&' in http_uri48 ):
  http_uri48 = re.sub( r'\&', r'\\x26', http_uri48 )
  if http_uri48.lower() in pcre_uri73.lower():
   http_uri48=""
   if debug1: print("ok trouvé grep48b ("+http_uri48+")")
 elif pcre_uri73 and http_uri48 and ( '=' in http_uri48 ):
  http_uri48 = re.sub( r'\=', r'\\x3D', http_uri48 )
  if http_uri48.lower() in pcre_uri73.lower():
   http_uri48=""
   if debug1: print("ok trouvé grep48c ("+http_uri48+")")
 if pcre_uri73 and http_uri53 and ( http_uri53.lower() in pcre_uri73.lower() ):
  http_uri53=""
  if debug1: print("ok trouvé grep53a ("+http_uri53+")")
 elif pcre_uri73 and http_uri53 and ( '&' in http_uri53 ):
  http_uri53 = re.sub( r'\&', r'\\x26', http_uri53 )
  if http_uri53.lower() in pcre_uri73.lower():
   http_uri53=""
   if debug1: print("ok trouvé grep53b ("+http_uri53+")")
 elif pcre_uri73 and http_uri53 and ( '=' in http_uri53 ):
  http_uri53 = re.sub( r'\=', r'\\x3D', http_uri53 )
  if http_uri53.lower() in pcre_uri73.lower():
   http_uri53=""
   if debug1: print("ok trouvé grep53c ("+http_uri53+")")
 if pcre_uri73 and http_uri58 and ( http_uri58.lower() in pcre_uri73.lower() ):
  http_uri58=""
  if debug1: print("ok trouvé grep58a ("+http_uri58+")")
 elif pcre_uri73 and http_uri58 and ( '&' in http_uri58 ):
  http_uri58 = re.sub( r'\&', r'\\x26', http_uri58 )
  if http_uri58.lower() in pcre_uri73.lower():
   http_uri58=""
   if debug1: print("ok trouvé grep58b ("+http_uri58+")")
 elif pcre_uri73 and http_uri58 and ( '=' in http_uri58 ):
  http_uri58 = re.sub( r'\=', r'\\x3D', http_uri58 )
  if http_uri58.lower() in pcre_uri73.lower():
   http_uri58=""
   if debug1: print("ok trouvé grep58c ("+http_uri58+")")
 if pcre_uri73 and http_uri63 and ( http_uri63.lower() in pcre_uri73.lower() ):
  http_uri63=""
  if debug1: print("ok trouvé grep63a ("+http_uri63+")")
 elif pcre_uri73 and http_uri63 and ( '&' in http_uri63 ):
  http_uri63 = re.sub( r'\&', r'\\x26', http_uri63 )
  if http_uri63.lower() in pcre_uri73.lower():
   http_uri63=""
   if debug1: print("ok trouvé grep63b ("+http_uri63+")")
 elif pcre_uri73 and http_uri63 and ( '=' in http_uri63 ):
  http_uri63 = re.sub( r'\=', r'\\x3D', http_uri63 )
  if http_uri63.lower() in pcre_uri73.lower():
   http_uri63=""
   if debug1: print("ok trouvé grep63c ("+http_uri63+")")

 if http_header68:
  if re.search(          r'User\\-Agent\\x3A\\x20(?!$)', http_header68, re.I):
   http_header68=re.sub( r'User\\-Agent\\x3A\\x20(?!$)', r'^', http_header68, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A\\x20$', http_header68, re.I):
   http_header68=re.sub( r'User\\-Agent\\x3A\\x20$', r'^', http_header68, flags=re.I)
   http_header68=""
  elif re.search(        r'User\\-Agent\\x3A (?!$)', http_header68, re.I):
   http_header68=re.sub( r'User\\-Agent\\x3A (?!$)', r'^', http_header68, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A $', http_header68, re.I):
   http_header68=""
  elif re.search(        r'User\-Agent\\x3A (?!$)', http_header68, re.I):
   http_header68=re.sub( r'User\-Agent\\x3A (?!$)', r'^', http_header68, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A $', http_header68, re.I):
   http_header68=""
  elif re.search(        r'User\\-Agent\\: (?!$)', http_header68, re.I):
   http_header68=re.sub( r'User\\-Agent\\: (?!$)', r'^', http_header68, flags=re.I)
  elif re.search(        r'User\\-Agent\\: $', http_header68, re.I):
   http_header68=""
  elif re.search(        r'User\-Agent\\: (?!$)', http_header68, re.I):
   http_header68=re.sub( r'User\-Agent\\: (?!$)', r'^', http_header68, flags=re.I)
  elif re.search(        r'User\-Agent\\: $', http_header68, re.I):
   http_header68=""
  elif re.search(        r'User\\-Agent\\x3A(?!$)', http_header68, re.I):
   http_header68=re.sub( r'User\\-Agent\\x3A(?!$)', r'^', http_header68, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A$', http_header68, re.I):
   http_header68=""
  elif re.search(        r'User\-Agent\\x3A(?!$)', http_header68, re.I):
   http_header68=re.sub( r'User\-Agent\\x3A(?!$)', r'^', http_header68, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A$', http_header68, re.I):
   http_header68=""
  elif re.search(        r'User\\-Agent\\:(?!$)', http_header68, re.I):
   http_header68=re.sub( r'User\\-Agent\\:(?!$)', r'^', http_header68, flags=re.I)
  elif re.search(        r'User\\-Agent\\:$', http_header68, re.I):
   http_header68=""
  elif re.search(        r'User\-Agent\\:(?!$)', http_header68, re.I):
   http_header68=re.sub( r'User\-Agent\\:(?!$)', r'^', http_header68, flags=re.I)
  elif re.search(        r'User\-Agent\\:$', http_header68, re.I):
   http_header68=""
  http_header68=re.sub(  r'\\x0D\\x0A', r'$', http_header68, flags=re.I)
 if http_header121:
  if re.search(           r'User\\-Agent\\x3A\\x20(?!$)', http_header121, re.I):
   http_header121=re.sub( r'User\\-Agent\\x3A\\x20(?!$)', r'^', http_header121, flags=re.I)
  elif re.search(         r'User\\-Agent\\x3A\\x20$', http_header121, re.I):
   http_header121=re.sub( r'User\\-Agent\\x3A\\x20$', r'^', http_header121, flags=re.I)
   http_header121=""
  elif re.search(         r'User\\-Agent\\x3A (?!$)', http_header121, re.I):
   http_header121=re.sub( r'User\\-Agent\\x3A (?!$)', r'^', http_header121, flags=re.I)
  elif re.search(         r'User\\-Agent\\x3A $', http_header121, re.I):
   http_header121=""
  elif re.search(         r'User\-Agent\\x3A (?!$)', http_header121, re.I):
   http_header121=re.sub( r'User\-Agent\\x3A (?!$)', r'^', http_header121, flags=re.I)
  elif re.search(         r'User\-Agent\\x3A $', http_header121, re.I):
   http_header121=""
  elif re.search(         r'User\\-Agent\\: (?!$)', http_header121, re.I):
   http_header121=re.sub( r'User\\-Agent\\: (?!$)', r'^', http_header121, flags=re.I)
  elif re.search(         r'User\\-Agent\\: $', http_header121, re.I):
   http_header121=""
  elif re.search(         r'User\-Agent\\: (?!$)', http_header121, re.I):
   http_header121=re.sub( r'User\-Agent\\: (?!$)', r'^', http_header121, flags=re.I)
  elif re.search(         r'User\-Agent\\: $', http_header121, re.I):
   http_header121=""
  elif re.search(         r'User\\-Agent\\x3A(?!$)', http_header121, re.I):
   http_header121=re.sub( r'User\\-Agent\\x3A(?!$)', r'^', http_header121, flags=re.I)
  elif re.search(         r'User\\-Agent\\x3A$', http_header121, re.I):
   http_header121=""
  elif re.search(         r'User\-Agent\\x3A(?!$)', http_header121, re.I):
   http_header121=re.sub( r'User\-Agent\\x3A(?!$)', r'^', http_header121, flags=re.I)
  elif re.search(         r'User\-Agent\\x3A$', http_header121, re.I):
   http_header121=""
  elif re.search(         r'User\\-Agent\:(?!$)', http_header121, re.I):
   http_header121=re.sub( r'User\\-Agent\:(?!$)', r'^', http_header121, flags=re.I)
  elif re.search(         r'User\\-Agent\:$', http_header121, re.I):
   http_header121=""
  elif re.search(         r'User\-Agent\\:(?!$)', http_header121, re.I):
   http_header121=re.sub( r'User\-Agent\\:(?!$)', r'^', http_header121, flags=re.I)
  elif re.search(         r'User\-Agent\\:$', http_header121, re.I):
   http_header121=""
  http_header121=re.sub(  r'\\x0D\\x0A', r'$', http_header121, flags=re.I)
 if http_header74:
  if re.search(          r'User\\-Agent\\x3A\\x20(?!$)', http_header74, re.I):
   http_header74=re.sub( r'User\\-Agent\\x3A\\x20(?!$)', r'^', http_header74, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A\\x20$', http_header74, re.I):
   http_header74=re.sub( r'User\\-Agent\\x3A\\x20$', r'^', http_header74, flags=re.I)
   http_header74=""
  elif re.search(        r'User\\-Agent\\x3A (?!$)', http_header74, re.I):
   http_header74=re.sub( r'User\\-Agent\\x3A (?!$)', r'^', http_header74, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A $', http_header74, re.I):
   http_header74=""
  elif re.search(        r'User\-Agent\\x3A (?!$)', http_header74, re.I):
   http_header74=re.sub( r'User\-Agent\\x3A (?!$)', r'^', http_header74, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A $', http_header74, re.I):
   http_header74=""
  elif re.search(        r'User\\-Agent\\: (?!$)', http_header74, re.I):
   http_header74=re.sub( r'User\\-Agent\\: (?!$)', r'^', http_header74, flags=re.I)
  elif re.search(        r'User\\-Agent\\: $', http_header74, re.I):
   http_header74=""
  elif re.search(        r'User\-Agent\\: (?!$)', http_header74, re.I):
   http_header74=re.sub( r'User\-Agent\\: (?!$)', r'^', http_header74, flags=re.I)
  elif re.search(        r'User\-Agent\\: $', http_header74, re.I):
   http_header74=""
  elif re.search(        r'User\\-Agent\\x3A(?!$)', http_header74, re.I):
   http_header74=re.sub( r'User\\-Agent\\x3A(?!$)', r'^', http_header74, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A$', http_header74, re.I):
   http_header74=""
  elif re.search(        r'User\-Agent\\x3A(?!$)', http_header74, re.I):
   http_header74=re.sub( r'User\-Agent\\x3A(?!$)', r'^', http_header74, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A$', http_header74, re.I):
   http_header74=""
  elif re.search(        r'User\\-Agent\\:(?!$)', http_header74, re.I):
   http_header74=re.sub( r'User\\-Agent\\:(?!$)', r'^', http_header74, flags=re.I)
  elif re.search(        r'User\\-Agent\\:$', http_header74, re.I):
   http_header74=""
  elif re.search(        r'User\-Agent\\:(?!$)', http_header74, re.I):
   http_header74=re.sub( r'User\-Agent\\:(?!$)', r'^', http_header74, flags=re.I)
  elif re.search(        r'User\-Agent\\:$', http_header74, re.I):
   http_header74=""
  http_header74=re.sub(  r'\\x0D\\x0A', r'$', http_header74, flags=re.I)

 if pcre_agent79:
  pcre_agent79 = re.sub( r'\^User\\-Agent\\x3A\\x20', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'\^User\\-Agent\\x3A ', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'(?<!\^)User\\-Agent\\x3A\\x20', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'(?<!\^)User\\-Agent\\x3A ', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'\^User\-Agent\\x3A\\x20', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'\^User\-Agent\\x3A ', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'(?<!\^)User\-Agent\\x3A\\x20', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'(?<!\^)User\-Agent\\x3A ', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'\^User\\-Agent\\:\\x20', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'\^User\\-Agent\\: ', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'(?<!\^)User\\-Agent\\:\\x20', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'(?<!\^)User\\-Agent\\: ', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'\^User\-Agent\\:\\x20', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'\^User\-Agent\\: ', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'(?<!\^)User\-Agent\\:\\x20', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'(?<!\^)User\-Agent\\: ', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'\^User\\-Agent\\x3A', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'(?<!\^)User\\-Agent\\x3A', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'\^User\-Agent\\x3A', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'(?<!\^)User\-Agent\\x3A', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'\^User\\-Agent\\:', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'(?<!\^)User\\-Agent\\:', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'\^User\-Agent\\:', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'(?<!\^)User\-Agent\\:', r'^', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'\\x0D\\x0A', r'$', pcre_agent79, flags=re.I )
  pcre_agent79 = re.sub( r'\\r\?\$', r'$', pcre_agent79, flags=re.I)
  pcre_agent79 = re.sub( r'\\r\$', r'$', pcre_agent79, flags=re.I)

 if http_header68:
  if re.search( r'\^Referer\\x3A\\x20', http_header68, re.I ):
   http_header68 = re.sub( r'\^Referer\\x3A\\x20', r'^', http_header68, flags=re.I)
   pcrereferer = http_header68
   http_header68 = ""
  if re.search( r'\^Referer\\x3A ', http_header68, re.I ):
   http_header68 = re.sub( r'\^Referer\\x3A ', r'^', http_header68, flags=re.I)
   pcrereferer = http_header68
   http_header68 = ""
  if re.search( r'(?<!\^)Referer\\x3A\\x20', http_header68, re.I ):
   http_header68 = re.sub( r'(?<!\^)Referer\\x3A\\x20', r'^', http_header68, flags=re.I)
   pcrereferer = http_header68
   http_header68 = ""
  if re.search( r'(?<!\^)Referer\\x3A ', http_header68, re.I ):
   http_header68 = re.sub( r'(?<!\^)Referer\\x3A ', r'^', http_header68, flags=re.I)
   pcrereferer = http_header68
   http_header68 = ""
  if re.search( r'\^Referer\\x3A', http_header68, re.I ):
   http_header68 = re.sub( r'\^Referer\\x3A', r'^', http_header68, flags=re.I)
   pcrereferer = http_header68
   http_header68 = ""
  if re.search( r'(?<!\^)Referer\\x3A', http_header68, re.I ):
   http_header68 = re.sub( r'(?<!\^)Referer\\x3A', r'^', http_header68, flags=re.I)
   pcrereferer = http_header68
   http_header68 = ""
 if http_header121:
  if re.search( r'\^Referer\\x3A\\x20', http_header121, re.I ):
   http_header121 = re.sub( r'\^Referer\\x3A\\x20', r'^', http_header121, flags=re.I)
   pcrereferer = http_header121
   http_header121 = ""
  if re.search( r'\^Referer\\x3A ', http_header121, re.I ):
   http_header121 = re.sub( r'\^Referer\\x3A ', r'^', http_header121, flags=re.I)
   pcrereferer = http_header121
   http_header121 = ""
  if re.search( r'(?<!\^)Referer\\x3A\\x20', http_header121, re.I ):
   http_header121 = re.sub( r'(?<!\^)Referer\\x3A\\x20', r'^', http_header121, flags=re.I)
   pcrereferer = http_header121
   http_header121 = ""
  if re.search( r'(?<!\^)Referer\\x3A ', http_header121, re.I ):
   http_header121 = re.sub( r'(?<!\^)Referer\\x3A ', r'^', http_header121, flags=re.I)
   pcrereferer = http_header121
   http_header121 = ""
  if re.search( r'\^Referer\\x3A', http_header121, re.I ):
   http_header121 = re.sub( r'\^Referer\\x3A', r'^', http_header121, flags=re.I)
   pcrereferer = http_header121
   http_header121 = ""
  if re.search( r'(?<!\^)Referer\\x3A', http_header121, re.I ):
   http_header121 = re.sub( r'(?<!\^)Referer\\x3A', r'^', http_header121, flags=re.I)
   pcrereferer = http_header121
   http_header121 = ""
 if http_header74:
  if re.search( r'\^Referer\\x3A\\x20', http_header74, re.I ):
   http_header74 = re.sub( r'\^Referer\\x3A\\x20', r'^', http_header74, flags=re.I)
   pcrereferer = http_header74
   http_header74 = ""
  if re.search( r'\^Referer\\x3A ', http_header74, re.I ):
   http_header74 = re.sub( r'\^Referer\\x3A ', r'^', http_header74, flags=re.I)
   pcrereferer = http_header74
   http_header74 = ""
  if re.search( r'(?<!\^)Referer\\x3A\\x20', http_header74, re.I ):
   http_header74 = re.sub( r'(?<!\^)Referer\\x3A\\x20', r'^', http_header74, flags=re.I)
   pcrereferer = http_header74
   http_header74 = ""
  if re.search( r'(?<!\^)Referer\\x3A ', http_header74, re.I ):
   http_header74 = re.sub( r'(?<!\^)Referer\\x3A ', r'^', http_header74, flags=re.I)
   pcrereferer = http_header74
   http_header74 = ""
  if re.search( r'\^Referer\\x3A', http_header74, re.I ):
   http_header74 = re.sub( r'\^Referer\\x3A', r'^', http_header74, flags=re.I)
   pcrereferer = http_header74
   http_header74 = ""
  if re.search( r'(?<!\^)Referer\\x3A', http_header74, re.I ):
   http_header74 = re.sub( r'(?<!\^)Referer\\x3A', r'^', http_header74, flags=re.I)
   pcrereferer = http_header74
   http_header74 = ""
 if pcre_agent79:
  if re.search( r'\^Referer\\x3A\\x20', pcre_agent79, re.I ):
   pcre_agent79 = re.sub( r'\^Referer\\x3A\\x20', r'^', pcre_agent79, flags=re.I)
   pcrereferer = pcre_agent79
   pcre_agent79 = ""
  if re.search( r'\^Referer\\x3A ', pcre_agent79, re.I ):
   pcre_agent79 = re.sub( r'\^Referer\\x3A ', r'^', pcre_agent79, flags=re.I)
   pcrereferer = pcre_agent79
   pcre_agent79 = ""
  if re.search( r'(?<!\^)Referer\\x3A\\x20', pcre_agent79, re.I ):
   pcre_agent79 = re.sub( r'(?<!\^)Referer\\x3A\\x20', r'^', pcre_agent79, flags=re.I)
   pcrereferer = pcre_agent79
   pcre_agent79 = ""
  if re.search( r'(?<!\^)Referer\\x3A ', pcre_agent79, re.I ):
   pcre_agent79 = re.sub( r'(?<!\^)Referer\\x3A ', r'^', pcre_agent79, flags=re.I)
   pcrereferer = pcre_agent79
   pcre_agent79 = ""
  if re.search( r'\^Referer\\x3A(?!\\x20)', pcre_agent79, re.I ):
   pcre_agent79 = re.sub( r'\^Referer\\x3A(?!\\x20)', r'^', pcre_agent79, flags=re.I)
   pcrereferer = pcre_agent79
   pcre_agent79 = ""
  if re.search( r'(?<!\^)Referer\\x3A(?!\\x20)', pcre_agent79, re.I ):
   pcre_agent79 = re.sub( r'(?<!\^)Referer\\x3A(?!\\x20)', r'^', pcre_agent79, flags=re.I)
   pcrereferer = pcre_agent79
   pcre_agent79 = ""

 if pcrereferer:
  pcrereferer=re.sub( r'\^\[\^\\r\\n\]\+\?', r'', pcrereferer, flags=re.I )
  pcrereferer=re.sub( r'\^\[\^\\r\\n\]\*\?', r'', pcrereferer, flags=re.I )
  pcrereferer=re.sub( r'\^\[\^\\r\\n\]\+', r'', pcrereferer, flags=re.I )
  pcrereferer=re.sub( r'\^\[\^\\r\\n\]\*', r'', pcrereferer, flags=re.I )
  pcrereferer=re.sub( r'\^\[\^\\n\]\+\?', r'', pcrereferer, flags=re.I )
  pcrereferer=re.sub( r'\^\[\^\\n\]\*\?', r'', pcrereferer, flags=re.I )
  pcrereferer=re.sub( r'\^\[\^\\n\]\+', r'', pcrereferer, flags=re.I )
  pcrereferer=re.sub( r'\^\[\^\\n\]\*', r'', pcrereferer, flags=re.I )

 if pcrereferer and not re.search( r'\\x', pcrereferer ) and re.search( r'^\^', pcrereferer ) and not re.search( r'^\^\\\-\$$', pcrereferer ) and not re.search( r'\(\?\!', pcrereferer ):
  pcrereferer=re.sub( r'\\', r'', pcrereferer )
  pcrereferer=re.sub( r'^\^', r'', pcrereferer )
  pcrereferer=re.sub( r'\$$', r'', pcrereferer )
  httpreferer=pcrereferer
  pcrereferer=0

 if pcre_agent79:
  pcre_agent79 = re.sub( r'\^\[\^\\r\\n\]\+\?', r'', pcre_agent79, flags=re.I )
  pcre_agent79 = re.sub( r'\^\[\^\\r\\n\]\*\?', r'', pcre_agent79, flags=re.I )
  pcre_agent79 = re.sub( r'\^\[\^\\r\\n\]\+', r'', pcre_agent79, flags=re.I )
  pcre_agent79 = re.sub( r'\^\[\^\\r\\n\]\*', r'', pcre_agent79, flags=re.I )
  pcre_agent79 = re.sub( r'\^\[\^\\n\]\+\?', r'', pcre_agent79, flags=re.I )
  pcre_agent79 = re.sub( r'\^\[\^\\n\]\*\?', r'', pcre_agent79, flags=re.I )
  pcre_agent79 = re.sub( r'\^\[\^\\n\]\+', r'', pcre_agent79, flags=re.I )
  pcre_agent79 = re.sub( r'\^\[\^\\n\]\*', r'', pcre_agent79, flags=re.I )

 if pcre_uri73:
  pcre_uri73 = re.sub( r'^\^\\\\/', r'^(?:https?\\:\\/\\/)?[^\\/]*?\\\/', pcre_uri73, flags=re.I )
  pcre_uri73 = re.sub( r'^\^\\\x2F', r'^(?:https?\\:\\/\\/)?[^\\/]*?\\\x2F', pcre_uri73, flags=re.I )

 # http_user_agent short
 if http_header68 and http_header74 and http_header121 and ( http_header68.__len__() >= ( http_header74.__len__() or http_header121.__len__() ) ):
  httpagentshort = http_header68
 elif http_header68 and http_header74 and http_header121 and ( http_header74.__len__() >= ( http_header68.__len__() or http_header121.__len__() ) ):
  httpagentshort = http_header74
 elif http_header68 and http_header74 and http_header121 and ( http_header121.__len__() >= ( http_header68.__len__() or http_header74.__len__() ) ):
  httpagentshort = http_header121
 elif http_header68 and http_header74 and not http_header121 and ( http_header68.__len__() >= http_header74.__len__() ):
  httpagentshort = http_header68
 elif http_header68 and http_header74 and not http_header121 and ( http_header74.__len__() >= http_header68.__len__() ):
  httpagentshort = http_header74
 elif http_header68 and http_header121 and not http_header74 and ( http_header68.__len__() >= http_header121.__len__() ):
  httpagentshort = http_header68
 elif http_header68 and http_header121 and not http_header74 and ( http_header121.__len__() >= http_header68.__len__() ):
  httpagentshort = http_header121
 elif http_header74 and http_header121 and not http_header68 and ( http_header74.__len__() >= http_header121.__len__() ):
  httpagentshort = http_header74
 elif http_header74 and http_header121 and not http_header68 and ( http_header121.__len__() >= http_header74.__len__() ):
  httpagentshort = http_header121
 elif http_header68 and not http_header74 and not http_header121:
  httpagentshort = http_header68
 elif http_header74 and not http_header68 and not http_header121:
  httpagentshort = http_header74
 elif http_header121 and not http_header68 and not http_header74:
  httpagentshort = http_header121

 if httpagentshort:
  httpagentshort = re.sub( r"\\x(..)", function_replacement_http_agent_short, httpagentshort)
  httpagentshort = re.sub( r'(?:\\(?!$)(?:x[a-f0-9]{2})?|\^|\$)', r'', httpagentshort)

 if pcre_agent79 and http_header68 and ( http_header68.lower() in pcre_agent79.lower() ) and ( '&' in http_header68 ):
  #http_header68 = re.sub( r'\&', r'\\x26', http_header68 ) # &
  http_header68 = ""
  if debug1: print("ok trouvé grep68a")
 elif pcre_agent79 and http_header68 and ( http_header68.lower() in pcre_agent79.lower() ) and ( '=' in http_header68 ):
  #http_header68 = re.sub( r'\=', r'\\x3D', http_header68 ) # =
  http_header68 = ""
  if debug1: print("ok trouvé grep68b")
 elif pcre_agent79 and http_header68 and ( http_header68.lower() in pcre_agent79.lower() ):
  http_header68 = ""
  if debug1: print("ok trouvé grep68c")
 if pcre_agent79 and http_header121 and ( http_header121.lower() in pcre_agent79.lower() ) and ( '&' in http_header121 ):
  #http_header121 = re.sub( r'\&', r'\\x26', http_header121 ) # &
  http_header121 = ""
  if debug1: print("ok trouvé grep121a")
 elif pcre_agent79 and http_header121 and ( http_header121.lower() in pcre_agent79.lower() ) and ( '=' in http_header121 ):
  #http_header121 = re.sub( r'\=', r'\\x3D', http_header121 ) # =
  http_header121 = ""
  if debug1: print("ok trouvé grep121b")
 elif pcre_agent79 and http_header121 and ( http_header121.lower() in pcre_agent79.lower() ):
  http_header121 = ""
  if debug1: print("ok trouvé grep121c")
 if pcre_agent79 and http_header74 and ( http_header74.lower() in pcre_agent79.lower() ) and ( '&' in http_header74 ):
  #http_header74 = re.sub( r'\&', r'\\x26', http_header74 ) # &
  http_header74 = ""
  if debug1: print("ok trouvé grep74a")
 elif pcre_agent79 and http_header74 and ( http_header74.lower() in pcre_agent79.lower() ) and ( '=' in http_header74 ):
  #http_header74 = re.sub( r'\=', r'\\x3D', http_header74 ) # =
  http_header74 = ""
  if debug1: print("ok trouvé grep74b")
 elif pcre_agent79 and http_header74 and ( http_header74.lower() in pcre_agent79.lower() ):
  http_header74 = ""
  if debug1: print("ok trouvé grep74c")

 # one uri
 #$abc1= "$pcre_uri73" if $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
 if pcre_uri73 and not http_uri03 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63: abc1 = pcre_uri73

 # one header
 if http_header68 and not http_header121 and not http_header74 and not pcre_agent79 and re.search( r'(?:\\|\^|\$)', http_header68 ): httppcreagent = http_header68
 if http_header121 and not http_header68 and not http_header74 and not pcre_agent79 and re.search( r'(?:\\|\^|\$)', http_header121 ): httppcreagent = http_header121
 if http_header74 and not http_header121 and not http_header68 and not pcre_agent79 and re.search( r'(?:\\|\^|\$)', http_header74 ): httppcreagent = http_header74
 if pcre_agent79 and not http_header68 and not http_header121 and not http_header74: httppcreagent = pcre_agent79

 # two headers
 if http_header68 and http_header74 and not http_header121 and ( distance75 or distance76 or distance77 or distance78 ):
  httppcreagent = '(?:'+http_header68+'.*?'+http_header74+')'
 elif http_header68 and http_header74 and not http_header121 and not ( distance75 or distance76 or distance77 or distance78 ):
  httppcreagent = '(?:'+http_header68+'.*?'+http_header74+'|'+http_header74+'.*?'+http_header68+')'
 elif http_header68 and not http_header74 and http_header121 and ( distance124 or distance125 or distance126 or distance127 or distance128 or distance129 ):
  httppcreagent = '(?:'+http_header68+'.*?'+http_header121+')'
 elif http_header68 and not http_header74 and http_header121 and not ( distance124 or distance125 or distance126 or distance127 or distance128 or distance129 ):
  httppcreagent = '(?:'+http_header68+'.*?'+http_header121+'|'+http_header121+'.*?'+http_header68+')'

 # two uri
 if ( distance9 or distance10 or distance11 or distance12 ) and not ( distance14 or distance15 or distance16 or distance17 ):
  if http_uri03 and http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: tableauuridistance1 = ( http_uri03.lower(), http_uri08.lower() )
  elif http_uri03 and http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and pcre_uri73: abc1 = '(?:'+http_uri03+'.*?'+http_uri08+')'
 elif not ( distance9 or distance10 or distance11 or distance12 ) and not ( distance14 or distance15 or distance16 or distance17 ):
  if http_uri03 and http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73 and not ( re.search( r'\\x|^\^|\$$', http_uri03 ) or re.search( r'\\x|^\^|\$$', http_uri08 ) ):
   #tableauuri1 = [ http_uri03, http_uri08 ] 
   #tableauuri1index=0
   #for uri in tableauuri1:
   # tableauuri1[tableauuri1index] = re.sub( r'\\(?!x)', r'', tableauuri1[tableauuri1index] )
   # if re.search( r'\\x|^\^|\$$', tableauuri1[tableauuri1index] ):
   #  tableauuri1=0

   http_uri03 = re.sub( r'\\(?!x)', r'', http_uri03)
   http_uri08 = re.sub( r'\\(?!x)', r'', http_uri08)
   if re.search( r'\\x|^\^|\$$', http_uri03 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri08 ):
    tableauuri1=0
   else:
    tableauuri1 = ( http_uri03.lower(), http_uri08.lower() )
  else:
   if http_uri03 and http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*?'+http_uri08+'|'+http_uri08+'.*?'+http_uri03+')'
   if http_uri03 and http_uri13 and not http_uri08 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*?'+http_uri13+'|'+http_uri13+'.*?'+http_uri03+')'
   if http_uri03 and http_uri18 and not http_uri08 and not http_uri13 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*?'+http_uri18+'|'+http_uri18+'.*?'+http_uri03+')'
   if http_uri03 and http_uri23 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*?'+http_uri23+'|'+http_uri23+'.*?'+http_uri03+')'
   if http_uri03 and http_uri28 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*?'+http_uri28+'|'+http_uri28+'.*?'+http_uri03+')'
   if http_uri03 and http_uri33 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*?'+http_uri33+'|'+http_uri33+'.*?'+http_uri03+')'
   if http_uri03 and http_uri38 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*?'+http_uri38+'|'+http_uri38+'.*?'+http_uri03+')'
   if http_uri03 and http_uri43 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*?'+http_uri43+'|'+http_uri43+'.*?'+http_uri03+')'
   if http_uri03 and http_uri48 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*?'+http_uri48+'|'+http_uri48+'.*?'+http_uri03+')'
   if http_uri03 and http_uri53 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*?'+http_uri53+'|'+http_uri53+'.*?'+http_uri03+')'
   if http_uri03 and http_uri58 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*?'+http_uri58+'|'+http_uri58+'.*?'+http_uri03+')'
   if http_uri03 and http_uri63 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*?'+http_uri63+'|'+http_uri63+'.*?'+http_uri03+')'
   if http_uri03 and pcre_uri73 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63: abc1 = '(?:'+http_uri03+'.*?'+pcre_uri73+'|'+pcre_uri73+'.*?'+http_uri03+')'

   if http_uri08 and pcre_uri73 and not http_uri03 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63: abc1 = '(?:'+http_uri08+'.*?'+pcre_uri73+'|'+pcre_uri73+'.*?'+http_uri08+')'
   if http_uri13 and pcre_uri73 and not http_uri03 and not http_uri08 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63: abc1 = '(?:'+http_uri13+'.*?'+pcre_uri73+'|'+pcre_uri73+'.*?'+http_uri13+')'
   if http_uri18 and pcre_uri73 and not http_uri03 and not http_uri08 and not http_uri13 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63: abc1 = '(?:'+http_uri18+'.*?'+pcre_uri73+'|'+pcre_uri73+'.*?'+http_uri18+')'
   if http_uri23 and pcre_uri73 and not http_uri03 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63: abc1 = '(?:'+http_uri23+'.*?'+pcre_uri73+'|'+pcre_uri73+'.*?'+http_uri23+')'
   if http_uri28 and pcre_uri73 and not http_uri03 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63: abc1 = '(?:'+http_uri28+'.*?'+pcre_uri73+'|'+pcre_uri73+'.*?'+http_uri28+')'
   if http_uri33 and pcre_uri73 and not http_uri03 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63: abc1 = '(?:'+http_uri33+'.*?'+pcre_uri73+'|'+pcre_uri73+'.*?'+http_uri33+')'
   if http_uri38 and pcre_uri73 and not http_uri03 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63: abc1 = '(?:'+http_uri38+'.*?'+pcre_uri73+'|'+pcre_uri73+'.*?'+http_uri38+')'
   if http_uri43 and pcre_uri73 and not http_uri03 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63: abc1 = '(?:'+http_uri43+'.*?'+pcre_uri73+'|'+pcre_uri73+'.*?'+http_uri43+')'
   if http_uri48 and pcre_uri73 and not http_uri03 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri53 and not http_uri58 and not http_uri63: abc1 = '(?:'+http_uri48+'.*?'+pcre_uri73+'|'+pcre_uri73+'.*?'+http_uri48+')'
   if http_uri53 and pcre_uri73 and not http_uri03 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri58 and not http_uri63: abc1 = '(?:'+http_uri53+'.*?'+pcre_uri73+'|'+pcre_uri73+'.*?'+http_uri53+')'
   if http_uri58 and pcre_uri73 and not http_uri03 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri63: abc1 = '(?:'+http_uri58+'.*?'+pcre_uri73+'|'+pcre_uri73+'.*?'+http_uri58+')'
   if http_uri63 and pcre_uri73 and not http_uri03 and not http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri63: abc1 = '(?:'+http_uri63+'.*?'+pcre_uri73+'|'+pcre_uri73+'.*?'+http_uri63+')'

 # three headers
 if ( distance75 or distance76 or distance77 or distance78 ) and ( distance124 or distance125 or distance128 or distance129 ):
  if http_header68 and http_header74 and http_header121 and not pcre_agent79: httppcreagent = '(?:'+http_header68+'.*'+http_header121+'.*'+http_header74+')'
 elif not ( distance75 or distance76 or distance77 or distance78 ) and not ( distance124 or distance125 or distance128 or distance129 ):
  if http_header68 and http_header121 and http_header74 and not pcre_agent79: httppcreagent = '(?:'+http_header68+'.*'+http_header121+'.*'+http_header74+'|'+http_header68+'.*'+http_header74+'.*'+http_header121+'|'+http_header74+'.*'+http_header68+'.*'+http_header121+'|'+http_header74+'.*'+http_header121+'.*'+http_header68+')'
  if http_header68 and http_header121 and pcre_agent79 and not http_header74: httppcreagent = '(?:'+http_header68+'.*'+http_header121+'.*'+pcre_agent79+'|'+http_header68+'.*'+pcre_agent79+'.*'+http_header121+'|'+pcre_agent79+'.*'+http_header68+'.*'+http_header121+'|'+pcre_agent79+'.*'+http_header121+'.*'+http_header68+')'

 # three uri
 if ( distance9 or distance10 or distance11 or distance12 ) and ( distance14 or distance15 or distance16 or distance17 ) and not ( distance19 or distance20 or distance21 or distance22 ):
  if http_uri03 and http_uri08 and http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: tableauuridistance1 = ( http_uri03.lower(), http_uri08.lower(), http_uri13.lower() )
  elif http_uri03 and http_uri08 and http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+')'
 elif not ( distance9 or distance10 or distance11 or distance12 ) and not ( distance14 or distance15 or distance16 or distance17 ) and not ( distance19 or distance20 or distance21 or distance22 ):
  if http_uri03 and http_uri08 and http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73 and not ( re.search( r'\\x|^\^|\$$', http_uri03 ) or re.search( r'\\x|^\^|\$$', http_uri08 ) or re.search( r'\\x|^\^|\$$', http_uri13 ) ):
   #tableauuri1 = [ http_uri03, http_uri08, http_uri13 ] 
   #tableauuri1index=0
   #for uri in tableauuri1:
   # tableauuri1[tableauuri1index] = re.sub( r'\\(?!x)', r'', tableauuri1[tableauuri1index] )
   # if re.search( r'\\x|^\^|\$$', tableauuri1[tableauuri1index] ):
   #  tableauuri1=0

   http_uri03 = re.sub( r'\\(?!x)', r'', http_uri03)
   http_uri08 = re.sub( r'\\(?!x)', r'', http_uri08)
   http_uri13 = re.sub( r'\\(?!x)', r'', http_uri13)
   if re.search( r'\\x|^\^|\$$', http_uri03 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri08 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri13 ):
    tableauuri1=0
   else:
    tableauuri1 = ( http_uri03.lower(), http_uri08.lower(), http_uri13.lower() )

  else:
   if http_uri03 and http_uri08 and http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+')'
   if http_uri03 and http_uri13 and http_uri08 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+')'
   if http_uri03 and http_uri18 and http_uri08 and not http_uri13 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri18+'|'+http_uri03+'.*'+http_uri18+'.*'+http_uri08+'|'+http_uri18+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri18+'.*'+http_uri03+')'
   if http_uri03 and http_uri23 and http_uri08 and not http_uri13 and not http_uri18 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri23+'|'+http_uri03+'.*'+http_uri23+'.*'+http_uri08+'|'+http_uri23+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri23+'.*'+http_uri03+')'
   if http_uri03 and http_uri28 and http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri28+'|'+http_uri03+'.*'+http_uri28+'.*'+http_uri08+'|'+http_uri28+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri28+'.*'+http_uri03+')'
   if http_uri03 and http_uri33 and http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri33+'|'+http_uri03+'.*'+http_uri33+'.*'+http_uri08+'|'+http_uri33+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri33+'.*'+http_uri03+')'
   if http_uri03 and http_uri38 and http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri38+'|'+http_uri03+'.*'+http_uri38+'.*'+http_uri08+'|'+http_uri38+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri38+'.*'+http_uri03+')'
   if http_uri03 and http_uri43 and http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri43+'|'+http_uri03+'.*'+http_uri43+'.*'+http_uri08+'|'+http_uri43+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri43+'.*'+http_uri03+')'
   if http_uri03 and http_uri48 and http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri48+'|'+http_uri03+'.*'+http_uri48+'.*'+http_uri08+'|'+http_uri48+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri48+'.*'+http_uri03+')'
   if http_uri03 and http_uri53 and http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri53+'|'+http_uri03+'.*'+http_uri53+'.*'+http_uri08+'|'+http_uri53+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri53+'.*'+http_uri03+')'
   if http_uri03 and http_uri58 and http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri58+'|'+http_uri03+'.*'+http_uri58+'.*'+http_uri08+'|'+http_uri58+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri58+'.*'+http_uri03+')'
   if http_uri03 and http_uri63 and http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri63+'|'+http_uri03+'.*'+http_uri63+'.*'+http_uri08+'|'+http_uri63+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri63+'.*'+http_uri03+')'
   if http_uri03 and pcre_uri73 and http_uri08 and not http_uri13 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+pcre_uri73+'|'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri08+'|'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri03+')'

 # four uri
 if ( distance9 or distance10 or distance11 or distance12 ) and ( distance14 or distance15 or distance16 or distance17 ) and ( distance19 or distance20 or distance21 or distance22 ) and not ( distance24 or distance25 or distance26 or distance27 ):
  if http_uri03 and http_uri08 and http_uri13 and http_uri18 and not pcre_uri73: tableauuridistance1 = ( http_uri03.lower(), http_uri08.lower(), http_uri13.lower(), http_uri18.lower() )
  elif http_uri03 and http_uri08 and http_uri13 and http_uri18 and pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri18+')'
 elif not ( distance9 or distance10 or distance11 or distance12 ) and not ( distance14 or distance15 or distance16 or distance17 ) and not ( distance19 or distance20 or distance21 or distance22 ) and not ( distance24 or distance25 or distance26 or distance27 ):
  if http_uri03 and http_uri08 and http_uri13 and http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73 and not ( re.search( r'\\x|^\^|\$$', http_uri03 ) or re.search( r'\\x|^\^|\$$', http_uri08 ) or re.search( r'\\x|^\^|\$$', http_uri13 ) or re.search( r'\\x|^\^|\$$', http_uri18 ) ):

   http_uri03 = re.sub( r'\\(?!x)', r'', http_uri03)
   http_uri08 = re.sub( r'\\(?!x)', r'', http_uri08)
   http_uri13 = re.sub( r'\\(?!x)', r'', http_uri13)
   http_uri18 = re.sub( r'\\(?!x)', r'', http_uri18)
   if re.search( r'\\x|^\^|\$$', http_uri03 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri08 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri13 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri18 ):
    tableauuri1=0
   else:
    tableauuri1 = ( http_uri03.lower(), http_uri08.lower(), http_uri13.lower(), http_uri18.lower() )

  else:
   if http_uri03 and http_uri08 and http_uri13 and http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri18+'|'+http_uri03+'.*'+http_uri08+'.*'+http_uri18+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri18+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri18+'.*'+http_uri08+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri18+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri18+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri18+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri18+'.*'+http_uri13+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri18+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri18+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri18+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri18+'|'+http_uri18+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri18+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri18+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'|'+http_uri18+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+')'
   if http_uri03 and http_uri08 and http_uri13 and http_uri23 and not http_uri18 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri23+'|'+http_uri03+'.*'+http_uri08+'.*'+http_uri23+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri23+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri23+'.*'+http_uri08+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri23+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri23+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri23+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri23+'.*'+http_uri13+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri23+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri23+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri23+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri23+'|'+http_uri23+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri23+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri23+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'|'+http_uri23+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+')'
   if http_uri03 and http_uri08 and http_uri13 and http_uri28 and not http_uri18 and not http_uri23 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri28+'|'+http_uri03+'.*'+http_uri08+'.*'+http_uri28+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri28+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri28+'.*'+http_uri08+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri28+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri28+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri28+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri28+'.*'+http_uri13+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri28+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri28+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri28+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri28+'|'+http_uri28+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri28+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri28+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'|'+http_uri28+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+')'
   if http_uri03 and http_uri08 and http_uri13 and http_uri33 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri33+'|'+http_uri03+'.*'+http_uri08+'.*'+http_uri33+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri33+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri33+'.*'+http_uri08+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri33+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri33+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri33+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri33+'.*'+http_uri13+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri33+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri33+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri33+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri33+'|'+http_uri33+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri33+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri33+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'|'+http_uri33+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+')'
   if http_uri03 and http_uri08 and http_uri13 and http_uri38 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri38+'|'+http_uri03+'.*'+http_uri08+'.*'+http_uri38+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri38+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri38+'.*'+http_uri08+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri38+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri38+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri38+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri38+'.*'+http_uri13+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri38+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri38+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri38+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri38+'|'+http_uri38+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri38+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri38+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'|'+http_uri38+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+')'
   if http_uri03 and http_uri08 and http_uri13 and http_uri43 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri43+'|'+http_uri03+'.*'+http_uri08+'.*'+http_uri43+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri43+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri43+'.*'+http_uri08+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri43+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri43+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri43+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri43+'.*'+http_uri13+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri43+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri43+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri43+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri43+'|'+http_uri43+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri43+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri43+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'|'+http_uri43+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+')'
   if http_uri03 and http_uri08 and http_uri13 and http_uri48 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri48+'|'+http_uri03+'.*'+http_uri08+'.*'+http_uri48+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri48+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri48+'.*'+http_uri08+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri48+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri48+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri48+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri48+'.*'+http_uri13+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri48+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri48+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri48+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri48+'|'+http_uri48+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri48+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri48+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'|'+http_uri48+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+')'
   if http_uri03 and http_uri08 and http_uri13 and http_uri53 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri58 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri53+'|'+http_uri03+'.*'+http_uri08+'.*'+http_uri53+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri53+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri53+'.*'+http_uri08+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri53+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri53+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri53+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri53+'.*'+http_uri13+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri53+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri53+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri53+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri53+'|'+http_uri53+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri53+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri53+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'|'+http_uri53+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+')'
   if http_uri03 and http_uri08 and http_uri13 and http_uri58 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri63 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri58+'|'+http_uri03+'.*'+http_uri08+'.*'+http_uri58+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri58+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri58+'.*'+http_uri08+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri58+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri58+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri58+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri58+'.*'+http_uri13+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri58+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri58+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri58+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri58+'|'+http_uri58+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri58+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri58+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'|'+http_uri58+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+')'
   if http_uri03 and http_uri08 and http_uri13 and http_uri63 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri63+'|'+http_uri03+'.*'+http_uri08+'.*'+http_uri63+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri63+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri63+'.*'+http_uri08+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri63+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri63+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri63+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri63+'.*'+http_uri13+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri63+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri63+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri63+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri63+'|'+http_uri63+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri63+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri63+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'|'+http_uri63+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+')'
   if http_uri03 and http_uri08 and http_uri13 and pcre_uri73 and not http_uri18 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+pcre_uri73+'|'+http_uri03+'.*'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+pcre_uri73+'|'+http_uri03+'.*'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri08+'|'+http_uri08+'.*'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+pcre_uri73+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+pcre_uri73+'|'+http_uri08+'.*'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri13+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+pcre_uri73+'|'+http_uri13+'.*'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+pcre_uri73+'|'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'|'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+')'

 # five uri
 if ( distance9 or distance10 or distance11 or distance12 ) and ( distance14 or distance15 or distance16 or distance17 ) and ( distance19 or distance20 or distance21 or distance22 ) and ( distance24 or distance25 or distance26 or distance27 ) and ( distance29 or distance30 or distance31 or distance32 ):
  if http_uri03 and http_uri08 and http_uri13 and http_uri18 and http_uri23 and not pcre_uri73: tableauuridistance1 = ( http_uri03.lower(), http_uri08.lower(), http_uri13.lower(), http_uri18.lower(), http_uri23.lower() )
  elif http_uri03 and http_uri08 and http_uri13 and http_uri18 and http_uri23 and pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri18+'.*'+http_uri23+')'
 elif not ( distance9 or distance10 or distance11 or distance12 ) and not ( distance14 or distance15 or distance16 or distance17 ) and not ( distance19 or distance20 or distance21 or distance22 ) and not ( distance24 or distance25 or distance26 or distance27 ) and not ( distance29 or distance30 or distance31 or distance32 ):
  if http_uri03 and http_uri08 and http_uri13 and http_uri18 and http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73 and not ( re.search( r'\\x|^\^|\$$', http_uri03 ) or re.search( r'\\x|^\^|\$$', http_uri08 ) or re.search( r'\\x|^\^|\$$', http_uri13 ) or re.search( r'\\x|^\^|\$$', http_uri18 ) or re.search( r'\\x|^\^|\$$', http_uri23 ) ):

   http_uri03 = re.sub( r'\\(?!x)', r'', http_uri03)
   http_uri08 = re.sub( r'\\(?!x)', r'', http_uri08)
   http_uri13 = re.sub( r'\\(?!x)', r'', http_uri13)
   http_uri18 = re.sub( r'\\(?!x)', r'', http_uri18)
   http_uri23 = re.sub( r'\\(?!x)', r'', http_uri23)
   if re.search( r'\\x|^\^|\$$', http_uri03 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri08 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri13 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri18 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri23 ):
    tableauuri1=0
   else:
    tableauuri1 = ( http_uri03.lower(), http_uri08.lower(), http_uri13.lower(), http_uri18.lower(), http_uri23.lower() )

  # if http_uri03 and http_uri08 and http_uri13 and http_uri18 and pcre_uri73 and not http_uri23 and not http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri18+'.*'+pcre_uri73+'|'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri18+'|'+http_uri03+'.*'+http_uri08+'.*'+http_uri18+'.*'+http_uri13+'.*'+pcre_uri73+'|'+http_uri03+'.*'+http_uri08+'.*'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri18+'|'+http_uri03+'.*'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri18+'.*'+pcre_uri73+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri18+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri18+'.*'+http_uri08+'.*'+pcre_uri73+'|'+http_uri03+'.*'+http_uri13+'.*'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri08+'|'+http_uri03+'.*'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri08+'|'+http_uri03+'.*'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri18+'|'+http_uri03+'.*'+http_uri18+'.*'+http_uri08+'.*'+http_uri13+'.*'+pcre_uri73+'|'+http_uri03+'.*'+http_uri18+'.*'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri13+'|'+http_uri03+'.*'+http_uri18+'.*'+http_uri13+'.*'+http_uri08+'.*'+pcre_uri73+'|'+http_uri03+'.*'+http_uri18+'.*'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri08+'|'+http_uri03+'.*'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri03+'.*'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri18+'.*'+http_uri13+'|'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri18+'|'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri18+'.*'+http_uri08+'|'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri18+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri18+'.*'+pcre_uri73+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri18+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri18+'.*'+http_uri13+'.*'+pcre_uri73+'|'+http_uri08+'.*'+http_uri03+'.*'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri13+'|'+http_uri08+'.*'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri18+'|'+http_uri08+'.*'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri13+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri18+'.*'+pcre_uri73+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri18+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri18+'.*'+http_uri03+'.*'+pcre_uri73+'|'+http_uri08+'.*'+http_uri13+'.*'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri18+'|'+http_uri08+'.*'+http_uri18+'.*'+http_uri03+'.*'+http_uri13+'.*'+pcre_uri73+'|'+http_uri08+'.*'+http_uri18+'.*'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri13+'|'+http_uri08+'.*'+http_uri18+'.*'+http_uri13+'.*'+http_uri03+'.*'+pcre_uri73+'|'+http_uri08+'.*'+http_uri18+'.*'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri03+'|'+http_uri08+'.*'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri13+'|'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri18+'.*'+http_uri13+'|'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri18+'|'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri03+'.*'+http_uri13+'|'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri13+'.*'+http_uri03+'|'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri18+'.*'+http_uri03+'|'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri18+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri18+'.*'+pcre_uri73+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri18+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri18+'.*'+http_uri08+'.*'+pcre_uri73+'|'+http_uri13+'.*'+http_uri03+'.*'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri18+'|'+http_uri13+'.*'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri18+'.*'+pcre_uri73+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri18+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri18+'.*'+http_uri03+'.*'+pcre_uri73+'|'+http_uri13+'.*'+http_uri08+'.*'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri18+'|'+http_uri13+'.*'+http_uri18+'.*'+http_uri03+'.*'+http_uri08+'.*'+pcre_uri73+'|'+http_uri13+'.*'+http_uri18+'.*'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri08+'|'+http_uri13+'.*'+http_uri18+'.*'+http_uri08+'.*'+http_uri03+'.*'+pcre_uri73+'|'+http_uri13+'.*'+http_uri18+'.*'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri13+'.*'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri08+'|'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri18+'.*'+http_uri08+'|'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri18+'|'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri03+'.*'+http_uri08+'|'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri18+'.*'+http_uri03+'|'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri18+'|'+http_uri18+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+pcre_uri73+'|'+http_uri18+'.*'+http_uri03+'.*'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri13+'|'+http_uri18+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+pcre_uri73+'|'+http_uri18+'.*'+http_uri03+'.*'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri08+'|'+http_uri18+'.*'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri18+'.*'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri18+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+pcre_uri73+'|'+http_uri18+'.*'+http_uri08+'.*'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri13+'|'+http_uri18+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+pcre_uri73+'|'+http_uri18+'.*'+http_uri08+'.*'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri03+'|'+http_uri18+'.*'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri03+'|'+http_uri18+'.*'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri13+'|'+http_uri18+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+pcre_uri73+'|'+http_uri18+'.*'+http_uri13+'.*'+http_uri03+'.*'+pcre_uri73+'.*'+http_uri08+'|'+http_uri18+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+pcre_uri73+'|'+http_uri18+'.*'+http_uri13+'.*'+http_uri08+'.*'+pcre_uri73+'.*'+http_uri03+'|'+http_uri18+'.*'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri18+'.*'+http_uri13+'.*'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri08+'|'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'|'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'|'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'|'+http_uri18+'.*'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'|'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri18+'|'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri18+'.*'+http_uri13+'|'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri18+'|'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri18+'.*'+http_uri08+'|'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri18+'.*'+http_uri08+'.*'+http_uri13+'|'+pcre_uri73+'.*'+http_uri03+'.*'+http_uri18+'.*'+http_uri13+'.*'+http_uri08+'|'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri18+'|'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri18+'.*'+http_uri13+'|'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri18+'|'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri18+'.*'+http_uri03+'|'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri18+'.*'+http_uri13+'.*'+http_uri03+'|'+pcre_uri73+'.*'+http_uri08+'.*'+http_uri18+'.*'+http_uri03+'.*'+http_uri13+'|'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri18+'|'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri18+'.*'+http_uri08+'|'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri18+'|'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri18+'.*'+http_uri03+'|'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri18+'.*'+http_uri08+'.*'+http_uri03+'|'+pcre_uri73+'.*'+http_uri13+'.*'+http_uri18+'.*'+http_uri03+'.*'+http_uri08+'|'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri03+'.*'+http_uri13+'.*'+http_uri08+'|'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'|'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri13+'.*'+http_uri03+'.*'+http_uri08+'|'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri13+'.*'+http_uri08+'.*'+http_uri03+'|'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri03+'|'+pcre_uri73+'.*'+http_uri18+'.*'+http_uri08+'.*'+http_uri03+'.*'+http_uri13+')'

 # six uri
 if ( distance9 or distance10 or distance11 or distance12 ) and ( distance14 or distance15 or distance16 or distance17 ) and ( distance19 or distance20 or distance21 or distance22 ) and ( distance24 or distance25 or distance26 or distance27 ) and ( distance29 or distance30 or distance31 or distance32 ) and not ( distance34 or distance35 or distance36 or distance37 ):
  if http_uri03 and http_uri08 and http_uri13 and http_uri18 and http_uri23 and http_uri28 and not pcre_uri73: tableauuridistance1 = ( http_uri03.lower(), http_uri08.lower(), http_uri13.lower(), http_uri18.lower(), http_uri23.lower(), http_uri28.lower() )
  elif http_uri03 and http_uri08 and http_uri13 and http_uri18 and http_uri23 and http_uri28 and pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri18+'.*'+http_uri23+'.*'+http_uri28+')'
 elif not ( distance9 or distance10 or distance11 or distance12 ) and not ( distance14 or distance15 or distance16 or distance17 ) and not ( distance19 or distance20 or distance21 or distance22 ) and not ( distance24 or distance25 or distance26 or distance27 ) and not ( distance29 or distance30 or distance31 or distance32 ) and not ( distance34 or distance35 or distance36 or distance37 ):
  if http_uri03 and http_uri08 and http_uri13 and http_uri18 and http_uri23 and http_uri28 and not http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73 and not ( re.search( r'\\x|^\^|\$$', http_uri03 ) or re.search( r'\\x|^\^|\$$', http_uri08 ) or re.search( r'\\x|^\^|\$$', http_uri13 ) or re.search( r'\\x|^\^|\$$', http_uri18 ) or re.search( r'\\x|^\^|\$$', http_uri23 ) or re.search( r'\\x|^\^|\$$', http_uri28 ) ):

   http_uri03 = re.sub( r'\\(?!x)', r'', http_uri03)
   http_uri08 = re.sub( r'\\(?!x)', r'', http_uri08)
   http_uri13 = re.sub( r'\\(?!x)', r'', http_uri13)
   http_uri18 = re.sub( r'\\(?!x)', r'', http_uri18)
   http_uri23 = re.sub( r'\\(?!x)', r'', http_uri23)
   http_uri28 = re.sub( r'\\(?!x)', r'', http_uri28)
   if re.search( r'\\x|^\^|\$$', http_uri03 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri08 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri13 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri18 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri23 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri28 ):
    tableauuri1=0
   else:
    tableauuri1 = ( http_uri03.lower(), http_uri08.lower(), http_uri13.lower(), http_uri18.lower(), http_uri23.lower(), http_uri28.lower() )

 # seven uri
 if ( distance9 or distance10 or distance11 or distance12 ) and ( distance14 or distance15 or distance16 or distance17 ) and ( distance19 or distance20 or distance21 or distance22 ) and ( distance24 or distance25 or distance26 or distance27 ) and ( distance29 or distance30 or distance31 or distance32 ) and ( distance34 or distance35 or distance36 or distance37 ):
  if http_uri03 and http_uri08 and http_uri13 and http_uri18 and http_uri23 and http_uri28 and http_uri33 and not pcre_uri73: tableauuridistance1 = ( http_uri03.lower(), http_uri08.lower(), http_uri13.lower(), http_uri18.lower(), http_uri23.lower(), http_uri28.lower(), http_uri33.lower() )
  elif http_uri03 and http_uri08 and http_uri13 and http_uri18 and http_uri23 and http_uri28 and http_uri33 and pcre_uri73: abc1 = '(?:'+http_uri03+'.*'+http_uri08+'.*'+http_uri13+'.*'+http_uri18+'.*'+http_uri23+'.*'+http_uri28+'.*'+http_uri33+')'
 elif not ( distance9 or distance10 or distance11 or distance12 ) and not ( distance14 or distance15 or distance16 or distance17 ) and not ( distance19 or distance20 or distance21 or distance22 ) and not ( distance24 or distance25 or distance26 or distance27 ) and not ( distance29 or distance30 or distance31 or distance32 ) and not ( distance34 or distance35 or distance36 or distance37 ):
  if http_uri03 and http_uri08 and http_uri13 and http_uri18 and http_uri23 and http_uri28 and http_uri33 and not http_uri38 and not http_uri43 and not http_uri48 and not http_uri53 and not http_uri58 and not http_uri63 and not pcre_uri73 and not ( re.search( r'\\x|^\^|\$$', http_uri03 ) or re.search( r'\\x|^\^|\$$', http_uri08 ) or re.search( r'\\x|^\^|\$$', http_uri13 ) or re.search( r'\\x|^\^|\$$', http_uri18 ) or re.search( r'\\x|^\^|\$$', http_uri23 ) or re.search( r'\\x|^\^|\$$', http_uri28 ) or re.search( r'\\x|^\^|\$$', http_uri33 ) ):

   http_uri03 = re.sub( r'\\(?!x)', r'', http_uri03)
   http_uri08 = re.sub( r'\\(?!x)', r'', http_uri08)
   http_uri13 = re.sub( r'\\(?!x)', r'', http_uri13)
   http_uri18 = re.sub( r'\\(?!x)', r'', http_uri18) 
   http_uri23 = re.sub( r'\\(?!x)', r'', http_uri23)
   http_uri28 = re.sub( r'\\(?!x)', r'', http_uri28)
   http_uri33 = re.sub( r'\\(?!x)', r'', http_uri33)
   if re.search( r'\\x|^\^|\$$', http_uri03 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri08 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri13 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri18 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri23 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri28 ):
    tableauuri1=0
   elif re.search( r'\\x|^\^|\$$', http_uri33 ):
    tableauuri1=0
   else:
    tableauuri1 = ( http_uri03.lower(), http_uri08.lower(), http_uri13.lower(), http_uri18.lower(), http_uri23.lower(), http_uri28.lower(), http_uri33.lower() )

 for key,value in enumerate(tableauuridistance1):
  if re.search( r'(?:\\(?!x[a-f0-9]{2}))', value): tableauuridistance2 += ( re.sub( r'(?:\\(?!x[a-f0-9]{2}))', r'', value), )
  elif re.search( r'(?:\\x..)', value): tableauuridistance2 += ( re.sub( r"\\x(..)", function_replacement_http_agent_short, value), )
  else: tableauuridistance2 += ( value, )
 tableauuridistance1 = tableauuridistance2

 # uri:
 abc1_nocase=0
 if http_urifast5:    abc1_nocase=http_urifast5
 if http_urinocase5:  abc1_nocase=http_urinocase5
 if http_urifast9:    abc1_nocase=http_urifast9
 if http_urinocase10: abc1_nocase=http_urinocase10
 if http_urifast14:   abc1_nocase=http_urifast14
 if http_urinocase12: abc1_nocase=http_urinocase12
 if http_urifast18:   abc1_nocase=http_urifast18
 if http_urinocase15: abc1_nocase=http_urinocase15
 if http_urifast23:   abc1_nocase=http_urifast23
 if http_urinocase19: abc1_nocase=http_urinocase19
 if http_urifast27:   abc1_nocase=http_urifast27
 if http_urinocase22: abc1_nocase=http_urinocase22
 if http_urifast32:   abc1_nocase=http_urifast32
 if http_urinocase26: abc1_nocase=http_urinocase26
 if http_urifast36:   abc1_nocase=http_urifast36
 if http_urinocase29: abc1_nocase=http_urinocase29
 if http_urifast41:   abc1_nocase=http_urifast41
 if http_urinocase33: abc1_nocase=http_urinocase33
 if http_urifast44:   abc1_nocase=http_urifast44
 if http_urinocase36: abc1_nocase=http_urinocase36
 if http_urifast49:   abc1_nocase=http_urifast49
 if http_urinocase40: abc1_nocase=http_urinocase40
 if http_urifast54:   abc1_nocase=http_urifast54
 if http_urinocase43: abc1_nocase=http_urinocase43
 if http_urifast58:   abc1_nocase=http_urifast58
 if http_urinocase47: abc1_nocase=http_urinocase47
 if http_urifast62:   abc1_nocase=http_urifast62
 if http_urinocase50: abc1_nocase=http_urinocase50
 if http_urinocase54: abc1_nocase=http_urinocase54
 if http_urinocase57: abc1_nocase=http_urinocase57
 if http_urinocase61: abc1_nocase=http_urinocase61
 if http_urinocase64: abc1_nocase=http_urinocase64
 if http_urinocase68: abc1_nocase=http_urinocase68
 if http_urinocase71: abc1_nocase=http_urinocase71
 if http_urinocase75: abc1_nocase=http_urinocase75
 if http_urinocase78: abc1_nocase=http_urinocase78
 if http_urinocase82: abc1_nocase=http_urinocase82
 if http_urinocase85: abc1_nocase=http_urinocase85
 if http_urinocase89: abc1_nocase=http_urinocase89
 if http_urinocase92: abc1_nocase=http_urinocase92

 # header:
 httppcreagent_nocase=0;
 if http_headernocase96: httppcreagent_nocase=http_headernocase96
 if http_headernocase99: httppcreagent_nocase=http_headernocase99
 if http_headerfast122: httppcreagent_nocase=http_headerfast122
 if http_headernocase123: httppcreagent_nocase=http_headernocase123
 if http_headerfast126: httppcreagent_nocase=http_headerfast126
 if http_headernocase127: httppcreagent_nocase=http_headernocase127
 if http_headerfast132: httppcreagent_nocase=http_headerfast132
 if http_headernocase104: httppcreagent_nocase=http_headernocase104
 if http_headerfast136: httppcreagent_nocase=http_headerfast136
 if http_headernocase107: httppcreagent_nocase=http_headernocase107

 if httpagentshort and httppcreagent:
  tempopcreagent = httppcreagent
  tempopcreagent = re.sub( r'\\(?!$)(?!x[a-f0-9]{2})', r'', tempopcreagent )
  if httpagentshort == tempopcreagent:
   if debug1: print("tempopcreagent: "+tempopcreagent)
   httppcreagent=0
   tempopcreagent=0

 if debug1 and httpuricourt:        print("httpuricourt1: "+etmsg1+", "+httpuricourt.lower())
 if debug1 and tableauuri1:         print("httpurilong1: "+etmsg1+", "+str(tableauuri1))
 if debug1 and abc1:                print("tableaupcreuri1: "+etmsg1+", "+str((abc1, abc1_nocase)))
 if debug1 and httppcreagent:       print("tableaupcreagent1: "+etmsg1+", "+str((httppcreagent, httppcreagent_nocase)))
 if debug1 and httpagentshort:      print("httpagentshort1: "+etmsg1+", "+httpagentshort.lower())
 if debug1 and http_method2:        print("tableauhttpmethod1: "+etmsg1+", "+str((http_method2, http_methodnocase3)))
 if debug1 and httpreferer:         print("httpreferer1: "+etmsg1+", "+httpreferer)
 if debug1 and pcrereferer:         print("tableaupcrereferer1: "+etmsg1+", "+pcrereferer)
 if debug1 and tableauuridistance1: print("tableauuridistance1: "+etmsg1+", "+str(tableauuridistance1))

 if httpuricourt:        dict[(etmsg1, 'httpuricourt')] = httpuricourt.lower()
 if httpagentshort:      dict[(etmsg1, 'httpagentshort')] = httpagentshort.lower()
 if http_method2:        dict[(etmsg1, 'httpmethod')] = (http_method2, http_methodnocase3)
 if httpreferer:         dict[(etmsg1, 'httpreferer')] = httpreferer
 if pcrereferer:         dict[(etmsg1, 'pcrereferer')] = pcrereferer
 if abc1:                dict[(etmsg1, 'pcreuri')] = (abc1, abc1_nocase)
 if httppcreagent:       dict[(etmsg1, 'pcreagent')] = (httppcreagent, httppcreagent_nocase)
 if tableauuri1:         dict[(etmsg1, 'httpurilong')] = tableauuri1
 if tableauuridistance1: dict[(etmsg1, 'httpurilongdistance')] = tableauuridistance1

 return; # function_match_http_uri()

#######################################################################################

def function_match_uricontent( lineet ):
 if debug1: print("brut2: "+lineet)
 etmsg1 = match_uricontent2.group(1)
 http_method2 = 0
 http_methodnocase3 = 0
 http_method2 = match_uricontent2.group(2)
 http_methodnocase3 = match_uricontent2.group(3)
 http_uri03 = match_uricontent2.group(4)
 http_urifast5 = match_uricontent2.group(5)
 http_urinocase5 = match_uricontent2.group(6)
 http_header06 = match_uricontent2.group(8)
 http_headernocase9 = match_uricontent2.group(9)
 http_headernocase12 = match_uricontent2.group(12)
 http_uri11 = match_uricontent2.group(18)
 http_urifast19 = match_uricontent2.group(19)
 http_urinocase16 = match_uricontent2.group(20)
 http_uri14 = match_uricontent2.group(23)
 http_urifast24 = match_uricontent2.group(24)
 http_urinocase20 = match_uricontent2.group(25)
 http_uri17 = match_uricontent2.group(28)
 http_urifast29 = match_uricontent2.group(29)
 http_urinocase23 = match_uricontent2.group(30)
 pcre_uri20 = match_uricontent2.group(33)

 # check what is http_uri best length ?
 httpuricourt=0
 http_uri03_length=0
 http_uri11_length=0
 http_uri14_length=0
 http_uri17_length=0
 if http_uri03: http_uri03_length=http_uri03.__len__()
 if http_uri11: http_uri11_length=http_uri11.__len__()
 if http_uri14: http_uri14_length=http_uri14.__len__()
 if http_uri17: http_uri17_length=http_uri17.__len__()
 if http_uri03_length >= http_uri11_length and http_uri03_length >= http_uri14_length and http_uri03_length >= http_uri17_length :
  httpuricourt=http_uri03
 elif http_uri11_length >= http_uri03_length and http_uri11_length >= http_uri14_length and http_uri11_length >= http_uri17_length :
  httpuricourt=http_uri11
 elif http_uri14_length >= http_uri03_length and http_uri14_length >= http_uri11_length and http_uri14_length >= http_uri17_length :
  httpuricourt=http_uri14
 elif http_uri17_length >= http_uri03_length and http_uri17_length >= http_uri11_length and http_uri17_length >= http_uri14_length :
  httpuricourt=http_uri17

 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri03 ) # (
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri03 ) # )
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri03 ) # *
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri03 ) # +
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri03 ) # -
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri03 ) # .
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri03 ) # /
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri03 ) # ?
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri03 ) # [
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri03 ) # ]
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri03 ) # ^
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri03 ) # {
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri03 ) # }
 if http_uri11: http_uri11 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri11 ) # (
 if http_uri11: http_uri11 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri11 ) # )
 if http_uri11: http_uri11 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri11 ) # *
 if http_uri11: http_uri11 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri11 ) # +
 if http_uri11: http_uri11 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri11 ) # -
 if http_uri11: http_uri11 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri11 ) # .
 if http_uri11: http_uri11 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri11 ) # /
 if http_uri11: http_uri11 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri11 ) # ?
 if http_uri11: http_uri11 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri11 ) # [
 if http_uri11: http_uri11 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri11 ) # ]
 if http_uri11: http_uri11 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri11 ) # ^
 if http_uri11: http_uri11 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri11 ) # {
 if http_uri11: http_uri11 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri11 ) # }
 if http_uri14: http_uri14 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri14 ) # (
 if http_uri14: http_uri14 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri14 ) # )
 if http_uri14: http_uri14 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri14 ) # *
 if http_uri14: http_uri14 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri14 ) # +
 if http_uri14: http_uri14 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri14 ) # -
 if http_uri14: http_uri14 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri14 ) # .
 if http_uri14: http_uri14 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri14 ) # /
 if http_uri14: http_uri14 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri14 ) # ?
 if http_uri14: http_uri14 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri14 ) # [
 if http_uri14: http_uri14 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri14 ) # ]
 if http_uri14: http_uri14 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri14 ) # ^
 if http_uri14: http_uri14 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri14 ) # {
 if http_uri14: http_uri14 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri14 ) # }
 if http_uri17: http_uri17 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri17 ) # (
 if http_uri17: http_uri17 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri17 ) # )
 if http_uri17: http_uri17 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri17 ) # *
 if http_uri17: http_uri17 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri17 ) # +
 if http_uri17: http_uri17 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri17 ) # -
 if http_uri17: http_uri17 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri17 ) # .
 if http_uri17: http_uri17 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri17 ) # /
 if http_uri17: http_uri17 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri17 ) # ?
 if http_uri17: http_uri17 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri17 ) # [
 if http_uri17: http_uri17 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri17 ) # ]
 if http_uri17: http_uri17 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri17 ) # ^
 if http_uri17: http_uri17 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri17 ) # {
 if http_uri17: http_uri17 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri17 ) # }
 #$pcre_uri20 =~ s/(?<!\x5C)\x24//g         if $pcre_uri20; # $

 if http_uri03: http_uri03 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri03)
 if http_header06: http_header06 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_header06)
 if http_uri11: http_uri11 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri11)
 if http_uri14: http_uri14 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri14)
 if http_uri17: http_uri17 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri17)
 # ne pas faire d'echappement sur la pcre ($pcre_uri20)

 abc1=0
 httppcreagent=0
 httpagentshort=0
 http_uri03b=0
 http_uri03c=0
 http_uri11b=0
 http_uri11c=0
 http_uri14b=0
 http_uri14c=0
 http_uri17b=0
 http_uri17c=0
 tableauuri1=0

 if http_header06:
  if re.search(          r'User\\-Agent\\x3A\\x20(?!$)', http_header06, re.I):
   http_header06=re.sub( r'User\\-Agent\\x3A\\x20(?!$)', r'^', http_header06, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A\\x20$', http_header06, re.I):
   http_header06=re.sub( r'User\\-Agent\\x3A\\x20$', r'^', http_header06, flags=re.I)
   http_header06=""
  elif re.search(        r'User\\-Agent\\x3A (?!$)', http_header06, re.I):
   http_header06=re.sub( r'User\\-Agent\\x3A (?!$)', r'^', http_header06, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A $', http_header06, re.I):
   http_header06=""
  elif re.search(        r'User\-Agent\\x3A (?!$)', http_header06, re.I):
   http_header06=re.sub( r'User\-Agent\\x3A (?!$)', r'^', http_header06, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A $', http_header06, re.I):
   http_header06=""
  elif re.search(        r'User\\-Agent\\: (?!$)', http_header06, re.I):
   http_header06=re.sub( r'User\\-Agent\\: (?!$)', r'^', http_header06, flags=re.I)
  elif re.search(        r'User\\-Agent\\: $', http_header06, re.I):
   http_header06=""
  elif re.search(        r'User\-Agent\\: (?!$)', http_header06, re.I):
   http_header06=re.sub( r'User\-Agent\\: (?!$)', r'^', http_header06, flags=re.I)
  elif re.search(        r'User\-Agent\\: $', http_header06, re.I):
   http_header06=""
  elif re.search(        r'User\\-Agent\\x3A(?!$)', http_header06, re.I):
   http_header06=re.sub( r'User\\-Agent\\x3A(?!$)', r'^', http_header06, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A$', http_header06, re.I):
   http_header06=""
  elif re.search(        r'User\-Agent\\x3A(?!$)', http_header06, re.I):
   http_header06=re.sub( r'User\-Agent\\x3A(?!$)', r'^', http_header06, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A$', http_header06, re.I):
   http_header06=""
  elif re.search(        r'User\\-Agent\\:(?!$)', http_header06, re.I):
   http_header06=re.sub( r'User\\-Agent\\:(?!$)', r'^', http_header06, flags=re.I)
  elif re.search(        r'User\\-Agent\\:$', http_header06, re.I):
   http_header06=""
  elif re.search(        r'User\-Agent\\:(?!$)', http_header06, re.I):
   http_header06=re.sub( r'User\-Agent\\:(?!$)', r'^', http_header06, flags=re.I)
  elif re.search(        r'User\-Agent\\:$', http_header06, re.I):
   http_header06=""
  http_header06=re.sub(  r'\\x0D\\x0A', r'$', http_header06, flags=re.I)

 if pcre_uri20:
  pcre_uri20 = re.sub( r'^\^\\\\/', r'^(?:https?\\:\\/\\/)?[^\\/]*?\\\/', pcre_uri20, flags=re.I )
  pcre_uri20 = re.sub( r'^\^\\\x2F', r'^(?:https?\\:\\/\\/)?[^\\/]*?\\\x2F', pcre_uri20, flags=re.I )

 # http_user_agent short
 if http_header06:
  httpagentshort = http_header06

 if httpagentshort:
  httpagentshort = re.sub( r"\\x(..)", function_replacement_http_agent_short, httpagentshort)
  httpagentshort = re.sub( r'(?:\\(?:x[a-f0-9]{2})?|\^|\$)', r'', httpagentshort)

 if pcre_uri20 and http_uri03 and ( http_uri03.lower() in pcre_uri20.lower() ):
  http_uri03=""
  if debug1: print("ok trouvé grep3a")
 elif pcre_uri20 and http_uri03 and ( '&' in http_uri03 ):
  http_uri03 = re.sub( r'\&', r'\\x26', http_uri03 )
  if http_uri03.lower() in pcre_uri20.lower():
   http_uri03=""
   if debug1: print("ok trouvé grep3b")
 elif pcre_uri20 and http_uri03 and ( '=' in http_uri03 ):
  http_uri03 = re.sub( r'\=', r'\\x3D', http_uri03 )
  if http_uri03.lower() in pcre_uri20.lower():
   http_uri03=""
   if debug1: print("ok trouvé grep3c")
 if pcre_uri20 and http_header06 and ( http_header06.lower() in pcre_uri20.lower() ):
  http_header06=""
  if debug1: print("ok trouvé grep6a")
 elif pcre_uri20 and http_header06 and ( '&' in http_header06 ):
  http_header06 = re.sub( r'\&', r'\\x26', http_header06 )
  if http_header06.lower() in pcre_uri20.lower():
   http_header06=""
   if debug1: print("ok trouvé grep6b")
 elif pcre_uri20 and http_header06 and ( '=' in http_header06 ):
  http_header06 = re.sub( r'\=', r'\\x3D', http_header06 )
  if http_header06.lower() in pcre_uri20.lower():
   http_header06=""
   if debug1: print("ok trouvé grep6c")
 if pcre_uri20 and http_uri11 and ( http_uri11.lower() in pcre_uri20.lower() ):
  http_uri11=""
  if debug1: print("ok trouvé grep11a")
 elif pcre_uri20 and http_uri11 and ( '&' in http_uri11 ):
  http_uri11 = re.sub( r'\&', r'\\x26', http_uri11 )
  if http_uri11.lower() in pcre_uri20.lower():
   http_uri11=""
   if debug1: print("ok trouvé grep11b")
 elif pcre_uri20 and http_uri11 and ( '=' in http_uri11 ):
  http_uri11 = re.sub( r'\=', r'\\x3D', http_uri11 )
  if http_uri11.lower() in pcre_uri20.lower():
   http_uri11=""
   if debug1: print("ok trouvé grep11c")
 if pcre_uri20 and http_uri14 and ( http_uri14.lower() in pcre_uri20.lower() ):
  http_uri14=""
  if debug1: print("ok trouvé grep14a")
 elif pcre_uri20 and http_uri14 and ( '&' in http_uri14 ):
  http_uri14 = re.sub( r'\&', r'\\x26', http_uri14 )
  if http_uri14.lower() in pcre_uri20.lower():
   http_uri14=""
   if debug1: print("ok trouvé grep14b")
 elif pcre_uri20 and http_uri14 and ( '=' in http_uri14 ):
  http_uri14 = re.sub( r'\=', r'\\x3D', http_uri14 )
  if http_uri14.lower() in pcre_uri20.lower():
   http_uri14=""
   if debug1: print("ok trouvé grep14c")
 if pcre_uri20 and http_uri17 and ( http_uri17.lower() in pcre_uri20.lower() ):
  http_uri17=""
  if debug1: print("ok trouvé grep17a")
 elif pcre_uri20 and http_uri17 and ( '&' in http_uri17 ):
  http_uri17 = re.sub( r'\&', r'\\x26', http_uri17 )
  if http_uri17.lower() in pcre_uri20.lower():
   http_uri17=""
   if debug1: print("ok trouvé grep17b")
 elif pcre_uri20 and http_uri17 and ( '=' in http_uri17 ):
  http_uri17 = re.sub( r'\=', r'\\x3D', http_uri17 )
  if http_uri17.lower() in pcre_uri20.lower():
   http_uri17=""
   if debug1: print("ok trouvé grep17c")

 # one uri
 #  $abc1= "$pcre_uri20" if $pcre_uri20 && !$http_uri03 && !$http_uri11 && !$http_uri14 && !$http_uri17;
 if pcre_uri20 and not http_uri03 and not http_uri11 and not http_uri14 and not http_uri17: abc1 = pcre_uri20

 # one header
 #$httppcreagent= "$http_header06" if $http_header06;

 # two uri
 if http_uri03 and http_uri11 and not http_uri14 and not http_uri17 and not pcre_uri20 and not ( re.search( r'\\x|^\^|\$$', http_uri03 ) or re.search( r'\\x|^\^|\$$', http_uri11 ) ):
  http_uri03 = re.sub( r'\\(?!x)', r'', http_uri03)
  http_uri11 = re.sub( r'\\(?!x)', r'', http_uri11)
  if re.search( r'\\x|^\^|\$$', http_uri03 ):
   tableauuri1=0
  elif re.search( r'\\x|^\^|\$$', http_uri11 ):
   tableauuri1=0
  else:
   tableauuri1 = ( http_uri03.lower(), http_uri11.lower() )
 elif http_uri03 and http_uri11 and not http_uri14 and not http_uri17 and not pcre_uri20: abc1 = '(?:'+http_uri03+'.*?'+http_uri11+'|'+http_uri11+'.*?'+http_uri03+')'

 if http_uri03 and http_uri14 and not http_uri11 and not http_uri17 and not pcre_uri20 and not ( re.search( r'\\x|^\^|\$$', http_uri03 ) or re.search( r'\\x|^\^|\$$', http_uri14 ) ):
  http_uri03 = re.sub( r'\\(?!x)', r'', http_uri03)
  http_uri14 = re.sub( r'\\(?!x)', r'', http_uri14)
  if re.search( r'\\x|^\^|\$$', http_uri03 ):
   tableauuri1=0
  elif re.search( r'\\x|^\^|\$$', http_uri14 ):
   tableauuri1=0
  else:
   tableauuri1 = ( http_uri03.lower(), http_uri14.lower() )
 elif http_uri03 and http_uri14 and not http_uri11 and not http_uri17 and not pcre_uri20: abc1 = '(?:'+http_uri03+'.*?'+http_uri14+'|'+http_uri14+'.*?'+http_uri03+')'

 if http_uri03 and http_uri17 and not http_uri11 and not http_uri14 and not pcre_uri20 and not ( re.search( r'\\x|^\^|\$$', http_uri03 ) or re.search( r'\\x|^\^|\$$', http_uri17 ) ):
  http_uri03 = re.sub( r'\\(?!x)', r'', http_uri03)
  http_uri17 = re.sub( r'\\(?!x)', r'', http_uri17)
  if re.search( r'\\x|^\^|\$$', http_uri03 ):
   tableauuri1=0
  elif re.search( r'\\x|^\^|\$$', http_uri17 ):
   tableauuri1=0
  else:
   tableauuri1 = ( http_uri03.lower(), http_uri17.lower() )
 elif http_uri03 and http_uri17 and not http_uri11 and not http_uri14 and not pcre_uri20: abc1 = '(?:'+http_uri03+'.*?'+http_uri17+'|'+http_uri17+'.*?'+http_uri03+')'

 if http_uri03 and pcre_uri20 and not http_uri11 and not http_uri14 and not http_uri17: abc1 = '(?:'+http_uri03+'.*?'+pcre_uri20+'|'+pcre_uri20+'.*?'+http_uri03+')'

 # three uri
 if http_uri03 and http_uri11 and http_uri14 and not http_uri17 and not pcre_uri20 and not ( re.search( r'\\x|^\^|\$$', http_uri03 ) or re.search( r'\\x|^\^|\$$', http_uri11 ) or re.search( r'\\x|^\^|\$$', http_uri14 ) ):
  http_uri03 = re.sub( r'\\(?!x)', r'', http_uri03)
  http_uri11 = re.sub( r'\\(?!x)', r'', http_uri11)
  http_uri14 = re.sub( r'\\(?!x)', r'', http_uri14)
  if re.search( r'\\x|^\^|\$$', http_uri03 ):
   tableauuri1=0
  elif re.search( r'\\x|^\^|\$$', http_uri11 ):
   tableauuri1=0
  elif re.search( r'\\x|^\^|\$$', http_uri14 ):
   tableauuri1=0
  else:
   tableauuri1 = ( http_uri03.lower(), http_uri11.lower(), http_uri14.lower() )
 elif http_uri03 and http_uri11 and http_uri14 and not http_uri17 and not pcre_uri20: abc1 = '(?:'+http_uri03+'.*'+http_uri11+'.*'+http_uri14+'|'+http_uri03+'.*'+http_uri14+'.*'+http_uri11+'|'+http_uri14+'.*'+http_uri11+'.*'+http_uri03+'|'+http_uri11+'.*'+http_uri14+'.*'+http_uri03+')'

 if http_uri03 and http_uri11 and http_uri17 and not http_uri14 and not pcre_uri20 and not ( re.search( r'\\x|^\^|\$$', http_uri03 ) or re.search( r'\\x|^\^|\$$', http_uri11 ) or re.search( r'\\x|^\^|\$$', http_uri17 ) ):
  http_uri03 = re.sub( r'\\(?!x)', r'', http_uri03)
  http_uri11 = re.sub( r'\\(?!x)', r'', http_uri11)
  http_uri17 = re.sub( r'\\(?!x)', r'', http_uri17)
  if re.search( r'\\x|^\^|\$$', http_uri03 ):
   tableauuri1=0
  elif re.search( r'\\x|^\^|\$$', http_uri11 ):
   tableauuri1=0
  elif re.search( r'\\x|^\^|\$$', http_uri17 ):
   tableauuri1=0
  else:
   tableauuri1 = ( http_uri03.lower(), http_uri11.lower(), http_uri17.lower() )
 elif http_uri03 and http_uri11 and http_uri17 and not http_uri14 and not pcre_uri20: abc1 = '(?:'+http_uri03+'.*'+http_uri11+'.*'+http_uri17+'|'+http_uri03+'.*'+http_uri17+'.*'+http_uri11+'|'+http_uri17+'.*'+http_uri11+'.*'+http_uri03+'|'+http_uri11+'.*'+http_uri17+'.*'+http_uri03+')'

 if http_uri03 and http_uri11 and pcre_uri20 and not http_uri14 and not http_uri17: abc1 = '(?:'+http_uri03+'.*'+http_uri11+'.*'+pcre_uri20+'|'+http_uri03+'.*'+pcre_uri20+'.*'+http_uri11+'|'+pcre_uri20+'.*'+http_uri11+'.*'+http_uri03+'|'+http_uri11+'.*'+pcre_uri20+'.*'+http_uri03+')'

 # four uri
 if http_uri03 and http_uri11 and http_uri14 and pcre_uri20 and not http_uri17:
  abc1= '(?:'+http_uri03+'.*'+http_uri11+'.*'+http_uri14+'.*'+pcre_uri20+'|'+http_uri03+'.*'+http_uri11+'.*'+pcre_uri20+'.*'+http_uri14+'|'+http_uri03+'.*'+http_uri14+'.*'+http_uri11+'.*'+pcre_uri20+'|'+http_uri03+'.*'+http_uri14+'.*'+pcre_uri20+'.*'+http_uri11+'|'+http_uri11+'.*'+http_uri14+'.*'+pcre_uri20+'.*'+http_uri03+'|'+http_uri11+'.*'+http_uri14+'.*'+http_uri03+'.*'+pcre_uri20+'|'+http_uri11+'.*'+http_uri03+'.*'+http_uri14+'.*'+pcre_uri20+'|'+http_uri11+'.*'+http_uri03+'.*'+pcre_uri20+'.*'+http_uri14+'|'+http_uri14+'.*'+http_uri03+'.*'+http_uri11+'.*'+pcre_uri20+'|'+http_uri14+'.*'+http_uri03+'.*'+pcre_uri20+'.*'+http_uri11+'|'+http_uri14+'.*'+http_uri11+'.*'+pcre_uri20+'.*'+http_uri03+'|'+http_uri14+'.*'+http_uri11+'.*'+http_uri03+'.*'+pcre_uri20+'|'+pcre_uri20+'.*'+http_uri03+'.*'+http_uri11+'.*'+http_uri14+'|'+pcre_uri20+'.*'+http_uri03+'.*'+http_uri14+'.*'+http_uri11+'|'+pcre_uri20+'.*'+http_uri14+'.*'+http_uri03+'.*'+http_uri11+'|'+pcre_uri20+'.*'+http_uri14+'.*'+http_uri11+'.*'+http_uri03+')'

 # uri:
 abc1_nocase=0
 if http_urifast5:    abc1_nocase=http_urifast5
 if http_urinocase5:  abc1_nocase=http_urinocase5
 if http_urifast19:   abc1_nocase=http_urifast19
 if http_urinocase16: abc1_nocase=http_urinocase16
 if http_urifast24:   abc1_nocase=http_urifast24
 if http_urinocase20: abc1_nocase=http_urinocase20
 if http_urifast29:   abc1_nocase=http_urifast29
 if http_urinocase23: abc1_nocase=http_urinocase23

 # header:
 httppcreagent_nocase=0;
 if http_headernocase9: httppcreagent_nocase=http_headernocase9
 if http_headernocase12: httppcreagent_nocase=http_headernocase12

 if debug1 and httpuricourt:   print("httpuricourt2: "+etmsg1+", "+httpuricourt.lower())
 if debug1 and tableauuri1:    print("httpurilong2: "+etmsg1+", "+str(tableauuri1))
 if debug1 and abc1:           print("tableaupcreuri2: "+etmsg1+", "+str((abc1, abc1_nocase)))
 if debug1 and httppcreagent:  print("tableaupcreagent2: "+etmsg1+", "+str((httppcreagent, httppcreagent_nocase)))
 if debug1 and httpagentshort: print("httpagentshort2: "+etmsg1+", "+httpagentshort.lower())
 if debug1 and http_method2:   print("tableauhttpmethod2: "+etmsg1+", "+str((http_method2, http_methodnocase3)))

 if httpuricourt:   dict[(etmsg1, 'httpuricourt')] = httpuricourt.lower()
 if httpagentshort: dict[(etmsg1, 'httpagentshort')] = httpagentshort.lower()
 if http_method2:   dict[(etmsg1, 'httpmethod')] = (http_method2, http_methodnocase3)
 if abc1:           dict[(etmsg1, 'pcreuri')] = (abc1, abc1_nocase)
 if httppcreagent:  dict[(etmsg1, 'pcreagent')] = (httppcreagent, httppcreagent_nocase)
 if tableauuri1:    dict[(etmsg1, 'httpurilong')] = tableauuri1

 return; # function_match_uricontent()

#######################################################################################

def function_match_uriheader( lineet ):
 if debug1: print("brut3: "+lineet)
 etmsg1 = match_uriheader2.group(1)
 http_method2 = 0
 http_methodnocase3 = 0
 http_method2 = match_uriheader2.group(2)
 http_methodnocase3 = match_uriheader2.group(3)
 http_uri03 = match_uriheader2.group(4)
 http_urifast5 = match_uriheader2.group(5)
 http_urinocase5 = match_uriheader2.group(6)
 http_urifast9 = match_uriheader2.group(9)
 http_urinocase8 = match_uriheader2.group(10)
 http_header08 = match_uriheader2.group(13)
 http_headerfast14 = match_uriheader2.group(14)
 http_headernocase12 = match_uriheader2.group(15)
 http_headerfast18 = match_uriheader2.group(18)
 http_headernocase15 = match_uriheader2.group(19)
 http_uri13 = match_uriheader2.group(22)
 http_urifast23 = match_uriheader2.group(23)
 http_urinocase19 = match_uriheader2.group(24)
 distance14 = match_uriheader2.group(25)
 distance15 = match_uriheader2.group(26)
 http_urifast27 = match_uriheader2.group(27)
 http_urinocase22 = match_uriheader2.group(28)
 distance16 = match_uriheader2.group(29)
 distance17 = match_uriheader2.group(30)
 http_header18 = match_uriheader2.group(31)
 http_headerfast32 = match_uriheader2.group(32)
 http_headernocase26 = match_uriheader2.group(33)
 distance34 = match_uriheader2.group(34)
 distance35 = match_uriheader2.group(35)
 http_headerfast36 = match_uriheader2.group(36)
 http_headernocase29 = match_uriheader2.group(37)
 distance38 = match_uriheader2.group(38)
 distance39 = match_uriheader2.group(39)
 pcre_uri23 = match_uriheader2.group(40)

 # check what is http_uri best length ?
 httpuricourt=0
 http_uri03_length=0
 http_uri13_length=0
 if http_uri03: http_uri03_length=http_uri03.__len__()
 if http_uri13: http_uri13_length=http_uri13.__len__()
 if http_uri03_length >= http_uri13_length :
  httpuricourt=http_uri03
 elif http_uri13_length >= http_uri03_length :
  httpuricourt=http_uri13

 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri03 ) # (
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri03 ) # )
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri03 ) # *
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri03 ) # +
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri03 ) # -
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri03 ) # .
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri03 ) # /
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri03 ) # ?
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri03 ) # [
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri03 ) # ]
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri03 ) # ^
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri03 ) # {
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri03 ) # }
 if http_header08: http_header08 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_header08 ) # (
 if http_header08: http_header08 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_header08 ) # )
 if http_header08: http_header08 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_header08 ) # *
 if http_header08: http_header08 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_header08 ) # +
 if http_header08: http_header08 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_header08 ) # -
 if http_header08: http_header08 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_header08 ) # .
 if http_header08: http_header08 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_header08 ) # /
 if http_header08: http_header08 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_header08 ) # ?
 if http_header08: http_header08 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_header08 ) # [
 if http_header08: http_header08 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_header08 ) # ]
 #if http_header08: http_header08 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_header08 ) # ^
 if http_header08: http_header08 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_header08 ) # {
 if http_header08: http_header08 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_header08 ) # }
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri13 ) # (
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri13 ) # )
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri13 ) # *
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri13 ) # +
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri13 ) # -
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri13 ) # .
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri13 ) # /
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri13 ) # ?
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri13 ) # [
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri13 ) # ]
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri13 ) # ^
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri13 ) # {
 if http_uri13: http_uri13 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri13 ) # }
 if http_header18: http_header18 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_header18 ) # (
 if http_header18: http_header18 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_header18 ) # )
 if http_header18: http_header18 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_header18 ) # *
 if http_header18: http_header18 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_header18 ) # +
 if http_header18: http_header18 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_header18 ) # -
 if http_header18: http_header18 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_header18 ) # .
 if http_header18: http_header18 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_header18 ) # /
 if http_header18: http_header18 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_header18 ) # ?
 if http_header18: http_header18 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_header18 ) # [
 if http_header18: http_header18 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_header18 ) # ]
 #if http_header18: http_header18 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_header18 ) # ^
 if http_header18: http_header18 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_header18 ) # {
 if http_header18: http_header18 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_header18 ) # }
 #$pcre_uri23 =~ s/(?<!\x5C)\x24//g         if $pcre_uri23; # $

 if http_uri03: http_uri03 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri03)
 if http_header08: http_header08 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_header08)
 if http_uri13: http_uri13 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri13)
 if http_header18: http_header18 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_header18)
 # ne pas faire d'echappement sur la pcre ($pcre_uri23)

 abc1=0
 httppcreagent=0
 httpagentshort=0
 httpreferer=0
 pcrereferer=0
 tableauuri1=0

 if http_header08:
  if re.search(          r'User\\-Agent\\x3A\\x20(?!$)', http_header08, re.I):
   http_header08=re.sub( r'User\\-Agent\\x3A\\x20(?!$)', r'^', http_header08, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A\\x20$', http_header08, re.I):
   http_header08=re.sub( r'User\\-Agent\\x3A\\x20$', r'^', http_header08, flags=re.I)
   http_header08=""
  elif re.search(        r'User\\-Agent\\x3A (?!$)', http_header08, re.I):
   http_header08=re.sub( r'User\\-Agent\\x3A (?!$)', r'^', http_header08, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A $', http_header08, re.I):
   http_header08=""
  elif re.search(        r'User\-Agent\\x3A (?!$)', http_header08, re.I):
   http_header08=re.sub( r'User\-Agent\\x3A (?!$)', r'^', http_header08, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A $', http_header08, re.I):
   http_header08=""
  elif re.search(        r'User\\-Agent\\: (?!$)', http_header08, re.I):
   http_header08=re.sub( r'User\\-Agent\\: (?!$)', r'^', http_header08, flags=re.I)
  elif re.search(        r'User\\-Agent\\: $', http_header08, re.I):
   http_header08=""
  elif re.search(        r'User\-Agent\\: (?!$)', http_header08, re.I):
   http_header08=re.sub( r'User\-Agent\\: (?!$)', r'^', http_header08, flags=re.I)
  elif re.search(        r'User\-Agent\\: $', http_header08, re.I):
   http_header08=""
  elif re.search(        r'User\\-Agent\\x3A(?!$)', http_header08, re.I):
   http_header08=re.sub( r'User\\-Agent\\x3A(?!$)', r'^', http_header08, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A$', http_header08, re.I):
   http_header08=""
  elif re.search(        r'User\-Agent\\x3A(?!$)', http_header08, re.I):
   http_header08=re.sub( r'User\-Agent\\x3A(?!$)', r'^', http_header08, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A$', http_header08, re.I):
   http_header08=""
  elif re.search(        r'User\\-Agent\\:(?!$)', http_header08, re.I):
   http_header08=re.sub( r'User\\-Agent\\:(?!$)', r'^', http_header08, flags=re.I)
  elif re.search(        r'User\\-Agent\\:$', http_header08, re.I):
   http_header08=""
  elif re.search(        r'User\-Agent\\:(?!$)', http_header08, re.I):
   http_header08=re.sub( r'User\-Agent\\:(?!$)', r'^', http_header08, flags=re.I)
  elif re.search(        r'User\-Agent\\:$', http_header08, re.I):
   http_header08=""
  http_header08=re.sub(  r'\\x0D\\x0A', r'$', http_header08, flags=re.I)
 if http_header18:
  if re.search(          r'User\\-Agent\\x3A\\x20(?!$)', http_header18, re.I):
   http_header18=re.sub( r'User\\-Agent\\x3A\\x20(?!$)', r'^', http_header18, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A\\x20$', http_header18, re.I):
   http_header18=re.sub( r'User\\-Agent\\x3A\\x20$', r'^', http_header18, flags=re.I)
   http_header18=""
  elif re.search(        r'User\\-Agent\\x3A (?!$)', http_header18, re.I):
   http_header18=re.sub( r'User\\-Agent\\x3A (?!$)', r'^', http_header18, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A $', http_header18, re.I):
   http_header18=""
  elif re.search(        r'User\-Agent\\x3A (?!$)', http_header18, re.I):
   http_header18=re.sub( r'User\-Agent\\x3A (?!$)', r'^', http_header18, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A $', http_header18, re.I):
   http_header18=""
  elif re.search(        r'User\\-Agent\\: (?!$)', http_header18, re.I):
   http_header18=re.sub( r'User\\-Agent\\: (?!$)', r'^', http_header18, flags=re.I)
  elif re.search(        r'User\\-Agent\\: $', http_header18, re.I):
   http_header18=""
  elif re.search(        r'User\-Agent\\: (?!$)', http_header18, re.I):
   http_header18=re.sub( r'User\-Agent\\: (?!$)', r'^', http_header18, flags=re.I)
  elif re.search(        r'User\-Agent\\: $', http_header18, re.I):
   http_header18=""
  elif re.search(        r'User\\-Agent\\x3A(?!$)', http_header18, re.I):
   http_header18=re.sub( r'User\\-Agent\\x3A(?!$)', r'^', http_header18, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A$', http_header18, re.I):
   http_header18=""
  elif re.search(        r'User\-Agent\\x3A(?!$)', http_header18, re.I):
   http_header18=re.sub( r'User\-Agent\\x3A(?!$)', r'^', http_header18, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A$', http_header18, re.I):
   http_header18=""
  elif re.search(        r'User\\-Agent\\:(?!$)', http_header18, re.I):
   http_header18=re.sub( r'User\\-Agent\\:(?!$)', r'^', http_header18, flags=re.I)
  elif re.search(        r'User\\-Agent\\:$', http_header18, re.I):
   http_header18=""
  elif re.search(        r'User\-Agent\\:(?!$)', http_header18, re.I):
   http_header18=re.sub( r'User\-Agent\\:(?!$)', r'^', http_header18, flags=re.I)
  elif re.search(        r'User\-Agent\\:$', http_header18, re.I):
   http_header18=""
  http_header18=re.sub(  r'\\x0D\\x0A', r'$', http_header18, flags=re.I)

 if http_header08:
  if re.search( r'\^Referer\\x3A\\x20', http_header08, re.I ):
   http_header08 = re.sub( r'\^Referer\\x3A\\x20', r'^', http_header08, flags=re.I)
   pcrereferer = http_header08
   http_header08 = ""
  if re.search( r'\^Referer\\x3A ', http_header08, re.I ):
   http_header08 = re.sub( r'\^Referer\\x3A ', r'^', http_header08, flags=re.I)
   pcrereferer = http_header08
   http_header08 = ""
  if re.search( r'(?<!\^)Referer\\x3A\\x20', http_header08, re.I ):
   http_header08 = re.sub( r'(?<!\^)Referer\\x3A\\x20', r'^', http_header08, flags=re.I)
   pcrereferer = http_header08
   http_header08 = ""
  if re.search( r'(?<!\^)Referer\\x3A ', http_header08, re.I ):
   http_header08 = re.sub( r'(?<!\^)Referer\\x3A ', r'^', http_header08, flags=re.I)
   pcrereferer = http_header08
   http_header08 = ""
  if re.search( r'\^Referer\\x3A', http_header08, re.I ):
   http_header08 = re.sub( r'\^Referer\\x3A', r'^', http_header08, flags=re.I)
   pcrereferer = http_header08
   http_header08 = ""
  if re.search( r'(?<!\^)Referer\\x3A', http_header08, re.I ):
   http_header08 = re.sub( r'(?<!\^)Referer\\x3A', r'^', http_header08, flags=re.I)
   pcrereferer = http_header08
   http_header08 = ""

 if http_header18:
  if re.search( r'\^Referer\\x3A\\x20', http_header18, re.I ):
   http_header18 = re.sub( r'\^Referer\\x3A\\x20', r'^', http_header18, flags=re.I)
   pcrereferer = http_header18
   http_header18 = ""
  if re.search( r'\^Referer\\x3A ', http_header18, re.I ):
   http_header18 = re.sub( r'\^Referer\\x3A ', r'^', http_header18, flags=re.I)
   pcrereferer = http_header18
   http_header18 = ""
  if re.search( r'(?<!\^)Referer\\x3A\\x20', http_header18, re.I ):
   http_header18 = re.sub( r'(?<!\^)Referer\\x3A\\x20', r'^', http_header18, flags=re.I)
   pcrereferer = http_header18
   http_header18 = ""
  if re.search( r'(?<!\^)Referer\\x3A ', http_header18, re.I ):
   http_header18 = re.sub( r'(?<!\^)Referer\\x3A ', r'^', http_header18, flags=re.I)
   pcrereferer = http_header18
   http_header18 = ""
  if re.search( r'\^Referer\\x3A', http_header18, re.I ):
   http_header18 = re.sub( r'\^Referer\\x3A', r'^', http_header18, flags=re.I)
   pcrereferer = http_header18
   http_header18 = ""
  if re.search( r'(?<!\^)Referer\\x3A', http_header18, re.I ):
   http_header18 = re.sub( r'(?<!\^)Referer\\x3A', r'^', http_header18, flags=re.I)
   pcrereferer = http_header18
   http_header18 = ""

 if pcrereferer and not re.search( r'\\x', pcrereferer ) and re.search( r'^\^', pcrereferer ) and not re.search( r'^\^\\\-\$$', pcrereferer ) and not re.search( r'\(\?\!', pcrereferer ):
  pcrereferer=re.sub( r'\\', r'', pcrereferer )
  pcrereferer=re.sub( r'^\^', r'', pcrereferer )
  pcrereferer=re.sub( r'\$$', r'', pcrereferer )
  httpreferer=pcrereferer
  pcrereferer=0

 if pcre_uri23:
  pcre_uri23 = re.sub( r'^\^\\\\/', r'^(?:https?\\:\\/\\/)?[^\\/]*?\\\/', pcre_uri23, flags=re.I )
  pcre_uri23 = re.sub( r'^\^\\\x2F', r'^(?:https?\\:\\/\\/)?[^\\/]*?\\\x2F', pcre_uri23, flags=re.I )

 # http_user_agent short
 if http_header08 and http_header18 and ( http_header08.__len__() >= ( http_header18.__len__() ) ):
  httpagentshort = http_header08
 elif http_header08 and http_header18 and ( http_header18.__len__() >= ( http_header08.__len__() ) ):
  httpagentshort = http_header18
 elif http_header08 and http_header18 and ( http_header121.__len__() >= ( http_header08.__len__() ) ):
  httpagentshort = http_header121
 elif http_header08 and not http_header18:
  httpagentshort = http_header08
 elif http_header18 and not http_header08:
  httpagentshort = http_header08

 if httpagentshort:
  httpagentshort = re.sub( r"\\x(..)", function_replacement_http_agent_short, httpagentshort)
  httpagentshort = re.sub( r'(?:\\(?!$)(?:x[a-f0-9]{2})?|\^|\$)', r'', httpagentshort)

 if pcre_uri23 and http_uri03 and ( http_uri03.lower() in pcre_uri23.lower() ):
  http_uri03=""
  if debug1: print("ok trouvé grep3a")
 elif pcre_uri23 and http_uri03 and ( '&' in http_uri03 ):
  http_uri03 = re.sub( r'\&', r'\\x26', http_uri03 )
  if http_uri03.lower() in pcre_uri23.lower():
   http_uri03=""
   if debug1: print("ok trouvé grep3b")
 elif pcre_uri23 and http_uri03 and ( '=' in http_uri03 ):
  http_uri03 = re.sub( r'\=', r'\\x3D', http_uri03 )
  if http_uri03.lower() in pcre_uri23.lower():
   http_uri03=""
   if debug1: print("ok trouvé grep3c")
 if pcre_uri23 and http_header08 and ( http_header08.lower() in pcre_uri23.lower() ):
  http_header08=""
  if debug1: print("ok trouvé grep8a")
 elif pcre_uri23 and http_header08 and ( '&' in http_header08 ):
  http_header08 = re.sub( r'\&', r'\\x26', http_header08 )
  if http_header08.lower() in pcre_uri23.lower():
   http_header08=""
   if debug1: print("ok trouvé grep8b")
 elif pcre_uri23 and http_header08 and ( '=' in http_header08 ):
  http_header08 = re.sub( r'\=', r'\\x3D', http_header08 )
  if http_header08.lower() in pcre_uri23.lower():
   http_header08=""
   if debug1: print("ok trouvé grep8c")
 if pcre_uri23 and http_uri13 and ( http_uri13.lower() in pcre_uri23.lower() ):
  http_uri13=""
  if debug1: print("ok trouvé grep13a")
 elif pcre_uri23 and http_uri13 and ( '&' in http_uri13 ):
  http_uri13 = re.sub( r'\&', r'\\x26', http_uri13 )
  if http_uri13.lower() in pcre_uri23.lower():
   http_uri13=""
   if debug1: print("ok trouvé grep13b")
 elif pcre_uri23 and http_uri13 and ( '=' in http_uri13 ):
  http_uri13 = re.sub( r'\=', r'\\x3D', http_uri13 )
  if http_uri13.lower() in pcre_uri23.lower():
   http_uri13=""
   if debug1: print("ok trouvé grep13c")
 if pcre_uri23 and http_header18 and ( http_header18.lower() in pcre_uri23.lower() ):
  http_header18=""
  if debug1: print("ok trouvé grep18a")
 elif pcre_uri23 and http_header18 and ( '&' in http_header18 ):
  http_header18 = re.sub( r'\&', r'\\x26', http_header18 )
  if http_header18.lower() in pcre_uri23.lower():
   http_header18=""
   if debug1: print("ok trouvé grep18b")
 elif pcre_uri23 and http_header18 and ( '=' in http_header18 ):
  http_header18 = re.sub( r'\=', r'\\x3D', http_header18 )
  if http_header18.lower() in pcre_uri23.lower():
   http_header18=""
   if debug1: print("ok trouvé grep18c")

 # one uri
 #$abc1= "$http_uri03" if $http_uri03 && !$http_uri13 && !$pcre_uri23;
 #$abc1= "$http_uri13" if $http_uri13 && !$http_uri03 && !$pcre_uri23;
 if pcre_uri23 and not http_uri03 and not http_uri13: abc1 = pcre_uri23

 # one header
 #$httppcreagent= "$http_header08" if $http_header08 && !$http_header18;
 #$httppcreagent= "$http_header18" if $http_header18 && !$http_header08;

 # two header
 if http_header08 and http_header18:
  httppcreagent = '(?:'+http_header08+'.*?'+http_header18+')'

 # two uri
 if http_uri03 and http_uri13 and not ( re.search( r'\\x|^\^|\$$', http_uri03 ) or re.search( r'\\x|^\^|\$$', http_uri13 ) ):
  http_uri03 = re.sub( r'\\(?!x)', r'', http_uri03)
  http_uri13 = re.sub( r'\\(?!x)', r'', http_uri13)
  if re.search( r'\\x|^\^|\$$', http_uri03 ):
   tableauuri1=0
  elif re.search( r'\\x|^\^|\$$', http_uri13 ):
   tableauuri1=0
  else:
   tableauuri1 = ( http_uri03.lower(), http_uri13.lower() )
 elif http_uri03 and http_uri13 and not pcre_uri23: abc1 = '(?:'+http_uri03+'.*?'+http_uri13+'|'+http_uri13+'.*?'+http_uri03+')'

 if http_uri03 and pcre_uri23 and not http_uri13: abc1 = '(?:'+http_uri03+'.*?'+pcre_uri23+'|'+pcre_uri23+'.*?'+http_uri03+')'

 # three uri
 if http_uri03 and http_uri13 and pcre_uri23: abc1 = '(?:'+http_uri03+'.*'+http_uri13+'.*'+pcre_uri23+'|'+http_uri03+'.*'+pcre_uri23+'.*'+http_uri13+'|'+pcre_uri23+'.*'+http_uri13+'.*'+http_uri03+'|'+http_uri13+'.*'+pcre_uri23+'.*'+http_uri03+')'

 # uri:
 abc1_nocase=0
 if http_urifast5:    abc1_nocase=http_urifast5
 if http_urinocase5:  abc1_nocase=http_urinocase5
 if http_urifast9:    abc1_nocase=http_urifast9
 if http_urinocase8: abc1_nocase=http_urinocase8
 if http_urifast23:   abc1_nocase=http_urifast23
 if http_urinocase19: abc1_nocase=http_urinocase19
 if http_urifast27:   abc1_nocase=http_urifast27
 if http_urinocase22: abc1_nocase=http_urinocase22
 # header:
 httppcreagent_nocase=0;
 if http_headerfast14: httppcreagent_nocase=http_headerfast14
 if http_headernocase12: httppcreagent_nocase=http_headernocase12
 if http_headerfast18: httppcreagent_nocase=http_headerfast18
 if http_headernocase15: httppcreagent_nocase=http_headernocase15
 if http_headerfast32: httppcreagent_nocase=http_headerfast32
 if http_headernocase26: httppcreagent_nocase=http_headernocase26
 if http_headerfast36: httppcreagent_nocase=http_headerfast36
 if http_headernocase29: httppcreagent_nocase=http_headernocase29

 if debug1 and httpuricourt:   print("httpuricourt3: "+etmsg1+", "+httpuricourt.lower())
 if debug1 and tableauuri1:    print("httpurilong3: "+etmsg1+", "+str(tableauuri1))
 if debug1 and abc1:           print("tableaupcreuri3: "+etmsg1+", "+str((abc1, abc1_nocase)))
 if debug1 and httppcreagent:  print("tableaupcreagent3: "+etmsg1+", "+str((httppcreagent, httppcreagent_nocase)))
 if debug1 and httpagentshort: print("httpagentshort3: "+etmsg1+", "+httpagentshort.lower())
 if debug1 and http_method2:   print("tableauhttpmethod3: "+etmsg1+", "+str((http_method2, http_methodnocase3)))
 if debug1 and httpreferer:    print("httpreferer3: "+etmsg1+", "+httpreferer)
 if debug1 and pcrereferer:    print("tableaupcrereferer3: "+etmsg1+", "+pcrereferer)

 if httpuricourt:   dict[(etmsg1, 'httpuricourt')] = httpuricourt.lower()
 if httpagentshort: dict[(etmsg1, 'httpagentshort')] = httpagentshort.lower()
 if http_method2:   dict[(etmsg1, 'httpmethod')] = (http_method2, http_methodnocase3)
 if httpreferer:    dict[(etmsg1, 'httpreferer')] = httpreferer
 if pcrereferer:    dict[(etmsg1, 'pcrereferer')] = pcrereferer
 if abc1:           dict[(etmsg1, 'pcreuri')] = (abc1, abc1_nocase)
 if httppcreagent:  dict[(etmsg1, 'pcreagent')] = (httppcreagent, httppcreagent_nocase)
 if tableauuri1:    dict[(etmsg1, 'httpurilong')] = tableauuri1

 return; # function_match_uriheader()

#######################################################################################

def function_match_http_header( lineet ):
 if debug1: print("brut4: "+lineet)
 etmsg1 = match_http_header2.group(1)
 http_method2 = 0
 http_methodnocase3 = 0
 http_method2 = match_http_header2.group(2)
 http_methodnocase3 = match_http_header2.group(3)
 http_header03 = match_http_header2.group(4)
 http_headerfast5 = match_http_header2.group(5)
 http_headernocase5 = match_http_header2.group(6)
 http_headerfast9 = match_http_header2.group(9)
 http_headernocase8 = match_http_header2.group(10)
 http_uri08 = match_http_header2.group(13)
 http_urifast14 = match_http_header2.group(14)
 http_urinocase12 = match_http_header2.group(15)
 http_urifast18 = match_http_header2.group(18)
 http_urinocase15 = match_http_header2.group(19)
 http_header13 = match_http_header2.group(22)
 http_headerfast23 = match_http_header2.group(23)
 http_headernocase19 = match_http_header2.group(24)
 distance14 = match_http_header2.group(25)
 distance15 = match_http_header2.group(26)
 http_headerfast27 = match_http_header2.group(27)
 http_headernocase22 = match_http_header2.group(28)
 distance16 = match_http_header2.group(29)
 distance17 = match_http_header2.group(30)
 http_uri18 = match_http_header2.group(31)
 http_urifast32 = match_http_header2.group(32)
 http_urinocase25 = match_http_header2.group(33)
 distance19 = match_http_header2.group(34)
 distance20 = match_http_header2.group(35)
 http_urifast36 = match_http_header2.group(36)
 http_urinocase28 = match_http_header2.group(37)
 distance21 = match_http_header2.group(38)
 distance22 = match_http_header2.group(39)
 http_header23 = match_http_header2.group(40)
 http_headerfast41 = match_http_header2.group(41)
 http_headernocase32 = match_http_header2.group(42)
 distance24 = match_http_header2.group(43)
 distance25 = match_http_header2.group(44)
 http_headerfast45 = match_http_header2.group(45)
 http_headernocase35 = match_http_header2.group(46)
 distance26 = match_http_header2.group(47)
 distance27 = match_http_header2.group(48)
 http_uri28 = match_http_header2.group(49)
 http_urifast50 = match_http_header2.group(50)
 http_urinocase39 = match_http_header2.group(51)
 distance29 = match_http_header2.group(52)
 distance30 = match_http_header2.group(53)
 http_urifast54 = match_http_header2.group(54)
 http_urinocase42 = match_http_header2.group(55)
 distance31 = match_http_header2.group(56)
 distance32 = match_http_header2.group(57)
 pcre_uri33 = match_http_header2.group(58)
 pcre_agent34 = match_http_header2.group(59)

 # check what is http_uri best length ?
 httpuricourt=0
 http_uri08_length=0
 http_uri18_length=0
 http_uri28_length=0
 if http_uri08: http_uri08_length=http_uri08.__len__()
 if http_uri18: http_uri18_length=http_uri18.__len__()
 if http_uri28: http_uri28_length=http_uri28.__len__()
 if http_uri08_length >= http_uri18_length and http_uri08_length >= http_uri28_length :
  httpuricourt=http_uri08
 elif http_uri18_length >= http_uri08_length and http_uri18_length >= http_uri28_length :
  httpuricourt=http_uri18
 elif http_uri28_length >= http_uri08_length and http_uri28_length >= http_uri18_length :
  httpuricourt=http_uri28

 if http_header03: http_header03 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_header03 ) # (
 if http_header03: http_header03 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_header03 ) # )
 if http_header03: http_header03 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_header03 ) # *
 if http_header03: http_header03 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_header03 ) # +
 if http_header03: http_header03 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_header03 ) # -
 if http_header03: http_header03 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_header03 ) # .
 if http_header03: http_header03 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_header03 ) # /
 if http_header03: http_header03 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_header03 ) # ?
 if http_header03: http_header03 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_header03 ) # [
 if http_header03: http_header03 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_header03 ) # ]
 #if http_header03: http_header03 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_header03 ) # ^
 if http_header03: http_header03 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_header03 ) # {
 if http_header03: http_header03 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_header03 ) # }
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri08 ) # (
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri08 ) # )
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri08 ) # *
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri08 ) # +
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri08 ) # -
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri08 ) # .
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri08 ) # /
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri08 ) # ?
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri08 ) # [
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri08 ) # ]
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri08 ) # ^
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri08 ) # {
 if http_uri08: http_uri08 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri08 ) # }
 if http_header13: http_header13 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_header13 ) # (
 if http_header13: http_header13 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_header13 ) # )
 if http_header13: http_header13 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_header13 ) # *
 if http_header13: http_header13 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_header13 ) # +
 if http_header13: http_header13 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_header13 ) # -
 if http_header13: http_header13 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_header13 ) # .
 if http_header13: http_header13 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_header13 ) # /
 if http_header13: http_header13 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_header13 ) # ?
 if http_header13: http_header13 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_header13 ) # [
 if http_header13: http_header13 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_header13 ) # ]
 #if http_header13: http_header13 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_header13 ) # ^
 if http_header13: http_header13 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_header13 ) # {
 if http_header13: http_header13 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_header13 ) # }
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri18 ) # (
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri18 ) # )
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri18 ) # *
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri18 ) # +
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri18 ) # -
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri18 ) # .
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri18 ) # /
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri18 ) # ?
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri18 ) # [
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri18 ) # ]
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri18 ) # ^
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri18 ) # {
 if http_uri18: http_uri18 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri18 ) # }
 if http_header23: http_header23 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_header23 ) # (
 if http_header23: http_header23 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_header23 ) # )
 if http_header23: http_header23 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_header23 ) # *
 if http_header23: http_header23 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_header23 ) # +
 if http_header23: http_header23 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_header23 ) # -
 if http_header23: http_header23 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_header23 ) # .
 if http_header23: http_header23 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_header23 ) # /
 if http_header23: http_header23 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_header23 ) # ?
 if http_header23: http_header23 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_header23 ) # [
 if http_header23: http_header23 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_header23 ) # ]
 #if http_header23: http_header23 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_header23 ) # ^
 if http_header23: http_header23 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_header23 ) # {
 if http_header23: http_header23 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_header23 ) # }
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri28 ) # (
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri28 ) # )
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri28 ) # *
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri28 ) # +
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri28 ) # -
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri28 ) # .
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri28 ) # /
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri28 ) # ?
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri28 ) # [
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri28 ) # ]
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri28 ) # ^
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri28 ) # {
 if http_uri28: http_uri28 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri28 ) # }
 #$pcre_uri33 =~ s/(?<!\x5C)\x24//g         if $pcre_uri33; # $
 #$pcre_agent34 =~ s/(?<!\x5C)\x24//g         if $pcre_agent34; # $

 if http_header03: http_header03 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_header03)
 if http_uri08: http_uri08 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri08)
 if http_header13: http_header13 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_header13)
 if http_uri18: http_uri18 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri18)
 if http_header23: http_header23 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_header23)
 if http_uri28: http_uri28 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri28)
 # ne pas faire d'echappement sur la pcre ($pcre_uri33 et $pcre_agent34)

 abc1=0
 httppcreagent=0
 httpagentshort=0
 httpreferer=0
 pcrereferer=0
 http_cookie=0
 cookiepcre=0
 tableauuri1=0

 if http_header03:
  if re.search(          r'User\\-Agent\\x3A\\x20(?!$)', http_header03, re.I):
   http_header03=re.sub( r'User\\-Agent\\x3A\\x20(?!$)', r'^', http_header03, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A\\x20$', http_header03, re.I):
   http_header03=re.sub( r'User\\-Agent\\x3A\\x20$', r'^', http_header03, flags=re.I)
   http_header03=""
  elif re.search(        r'User\\-Agent\\x3A (?!$)', http_header03, re.I):
   http_header03=re.sub( r'User\\-Agent\\x3A (?!$)', r'^', http_header03, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A $', http_header03, re.I):
   http_header03=""
  elif re.search(        r'User\-Agent\\x3A (?!$)', http_header03, re.I):
   http_header03=re.sub( r'User\-Agent\\x3A (?!$)', r'^', http_header03, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A $', http_header03, re.I):
   http_header03=""
  elif re.search(        r'User\\-Agent\\: (?!$)', http_header03, re.I):
   http_header03=re.sub( r'User\\-Agent\\: (?!$)', r'^', http_header03, flags=re.I)
  elif re.search(        r'User\\-Agent\\: $', http_header03, re.I):
   http_header03=""
  elif re.search(        r'User\-Agent\\: (?!$)', http_header03, re.I):
   http_header03=re.sub( r'User\-Agent\\: (?!$)', r'^', http_header03, flags=re.I)
  elif re.search(        r'User\-Agent\\: $', http_header03, re.I):
   http_header03=""
  elif re.search(        r'User\\-Agent\\x3A(?!$)', http_header03, re.I):
   http_header03=re.sub( r'User\\-Agent\\x3A(?!$)', r'^', http_header03, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A$', http_header03, re.I):
   http_header03=""
  elif re.search(        r'User\-Agent\\x3A(?!$)', http_header03, re.I):
   http_header03=re.sub( r'User\-Agent\\x3A(?!$)', r'^', http_header03, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A$', http_header03, re.I):
   http_header03=""
  elif re.search(        r'User\\-Agent\\:(?!$)', http_header03, re.I):
   http_header03=re.sub( r'User\\-Agent\\:(?!$)', r'^', http_header03, flags=re.I)
  elif re.search(        r'User\\-Agent\\:$', http_header03, re.I):
   http_header03=""
  elif re.search(        r'User\-Agent\\:(?!$)', http_header03, re.I):
   http_header03=re.sub( r'User\-Agent\\:(?!$)', r'^', http_header03, flags=re.I)
  elif re.search(        r'User\-Agent\\:$', http_header03, re.I):
   http_header03=""
  #http_header03=re.sub(  r'(?!^)\\x0D\\x0A', r'$', http_header03, flags=re.I)
 if http_header13:
  if re.search(          r'User\\-Agent\\x3A\\x20(?!$)', http_header13, re.I):
   http_header13=re.sub( r'User\\-Agent\\x3A\\x20(?!$)', r'^', http_header13, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A\\x20$', http_header13, re.I):
   http_header13=re.sub( r'User\\-Agent\\x3A\\x20$', r'^', http_header13, flags=re.I)
   http_header13=""
  elif re.search(        r'User\\-Agent\\x3A (?!$)', http_header13, re.I):
   http_header13=re.sub( r'User\\-Agent\\x3A (?!$)', r'^', http_header13, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A $', http_header13, re.I):
   http_header13=""
  elif re.search(        r'User\-Agent\\x3A (?!$)', http_header13, re.I):
   http_header13=re.sub( r'User\-Agent\\x3A (?!$)', r'^', http_header13, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A $', http_header13, re.I):
   http_header13=""
  elif re.search(        r'User\\-Agent\\: (?!$)', http_header13, re.I):
   http_header13=re.sub( r'User\\-Agent\\: (?!$)', r'^', http_header13, flags=re.I)
  elif re.search(        r'User\\-Agent\\: $', http_header13, re.I):
   http_header13=""
  elif re.search(        r'User\-Agent\\: (?!$)', http_header13, re.I):
   http_header13=re.sub( r'User\-Agent\\: (?!$)', r'^', http_header13, flags=re.I)
  elif re.search(        r'User\-Agent\\: $', http_header13, re.I):
   http_header13=""
  elif re.search(        r'User\\-Agent\\x3A(?!$)', http_header13, re.I):
   http_header13=re.sub( r'User\\-Agent\\x3A(?!$)', r'^', http_header13, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A$', http_header13, re.I):
   http_header13=""
  elif re.search(        r'User\-Agent\\x3A(?!$)', http_header13, re.I):
   http_header13=re.sub( r'User\-Agent\\x3A(?!$)', r'^', http_header13, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A$', http_header13, re.I):
   http_header13=""
  elif re.search(        r'User\\-Agent\\:(?!$)', http_header13, re.I):
   http_header13=re.sub( r'User\\-Agent\\:(?!$)', r'^', http_header13, flags=re.I)
  elif re.search(        r'User\\-Agent\\:$', http_header13, re.I):
   http_header13=""
  elif re.search(        r'User\-Agent\\:(?!$)', http_header13, re.I):
   http_header13=re.sub( r'User\-Agent\\:(?!$)', r'^', http_header13, flags=re.I)
  elif re.search(        r'User\-Agent\\:$', http_header13, re.I):
   http_header13=""
  #http_header13=re.sub(  r'(?!^)\\x0D\\x0A', r'$', http_header13, flags=re.I)
 if http_header23:
  if re.search(          r'User\\-Agent\\x3A\\x20(?!$)', http_header23, re.I):
   http_header23=re.sub( r'User\\-Agent\\x3A\\x20(?!$)', r'^', http_header23, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A\\x20$', http_header23, re.I):
   http_header23=re.sub( r'User\\-Agent\\x3A\\x20$', r'^', http_header23, flags=re.I)
   http_header23=""
  elif re.search(        r'User\\-Agent\\x3A (?!$)', http_header23, re.I):
   http_header23=re.sub( r'User\\-Agent\\x3A (?!$)', r'^', http_header23, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A $', http_header23, re.I):
   http_header23=""
  elif re.search(        r'User\-Agent\\x3A (?!$)', http_header23, re.I):
   http_header23=re.sub( r'User\-Agent\\x3A (?!$)', r'^', http_header23, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A $', http_header23, re.I):
   http_header23=""
  elif re.search(        r'User\\-Agent\\: (?!$)', http_header23, re.I):
   http_header23=re.sub( r'User\\-Agent\\: (?!$)', r'^', http_header23, flags=re.I)
  elif re.search(        r'User\\-Agent\\: $', http_header23, re.I):
   http_header23=""
  elif re.search(        r'User\-Agent\\: (?!$)', http_header23, re.I):
   http_header23=re.sub( r'User\-Agent\\: (?!$)', r'^', http_header23, flags=re.I)
  elif re.search(        r'User\-Agent\\: $', http_header23, re.I):
   http_header23=""
  elif re.search(        r'User\\-Agent\\x3A(?!$)', http_header23, re.I):
   http_header23=re.sub( r'User\\-Agent\\x3A(?!$)', r'^', http_header23, flags=re.I)
  elif re.search(        r'User\\-Agent\\x3A$', http_header23, re.I):
   http_header23=""
  elif re.search(        r'User\-Agent\\x3A(?!$)', http_header23, re.I):
   http_header23=re.sub( r'User\-Agent\\x3A(?!$)', r'^', http_header23, flags=re.I)
  elif re.search(        r'User\-Agent\\x3A$', http_header23, re.I):
   http_header23=""
  elif re.search(        r'User\\-Agent\\:(?!$)', http_header23, re.I):
   http_header23=re.sub( r'User\\-Agent\\:(?!$)', r'^', http_header23, flags=re.I)
  elif re.search(        r'User\\-Agent\\:$', http_header23, re.I):
   http_header23=""
  elif re.search(        r'User\-Agent\\:(?!$)', http_header23, re.I):
   http_header23=re.sub( r'User\-Agent\\:(?!$)', r'^', http_header23, flags=re.I)
  elif re.search(        r'User\-Agent\\:$', http_header23, re.I):
   http_header23=""
  #http_header23=re.sub(  r'(?!^)\\x0D\\x0A', r'$', http_header23, flags=re.I)

 if pcre_agent34:
  pcre_agent34 = re.sub( r'\^User\\-Agent\\x3A\\x20', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'\^User\\-Agent\\x3A ', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'(?<!\^)User\\-Agent\\x3A\\x20', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'(?<!\^)User\\-Agent\\x3A ', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'\^User\-Agent\\x3A\\x20', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'\^User\-Agent\\x3A ', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'(?<!\^)User\-Agent\\x3A\\x20', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'(?<!\^)User\-Agent\\x3A ', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'\^User\\-Agent\\:\\x20', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'\^User\\-Agent\\: ', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'(?<!\^)User\\-Agent\\:\\x20', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'(?<!\^)User\\-Agent\\: ', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'\^User\-Agent\\:\\x20', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'\^User\-Agent\\: ', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'(?<!\^)User\-Agent\\:\\x20', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'(?<!\^)User\-Agent\\: ', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'\^User\\-Agent\\x3A', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'(?<!\^)User\\-Agent\\x3A', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'\^User\-Agent\\x3A', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'(?<!\^)User\-Agent\\x3A', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'\^User\\-Agent\\:', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'(?<!\^)User\\-Agent\\:', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'\^User\-Agent\\:', r'^', pcre_agent34, flags=re.I)
  pcre_agent34 = re.sub( r'(?<!\^)User\-Agent\\:', r'^', pcre_agent34, flags=re.I)
  #pcre_agent34 = re.sub( r'\\x0D\\x0A', r'$', pcre_agent34, flags=re.I )
  #pcre_agent34 = re.sub( r'\\r\?\$', r'$', pcre_agent34, flags=re.I)
  #pcre_agent34 = re.sub( r'\\r\$', r'$', pcre_agent34, flags=re.I)

 if http_header03:
  if re.search( r'\^Referer\\x3A\\x20', http_header03, re.I ):
   http_header03 = re.sub( r'\^Referer\\x3A\\x20', r'^', http_header03, flags=re.I)
   pcrereferer = http_header03
   http_header03 = ""
  if re.search( r'\^Referer\\x3A ', http_header03, re.I ):
   http_header03 = re.sub( r'\^Referer\\x3A ', r'^', http_header03, flags=re.I)
   pcrereferer = http_header03
   http_header03 = ""
  if re.search( r'(?<!\^)Referer\\x3A\\x20', http_header03, re.I ):
   http_header03 = re.sub( r'(?<!\^)Referer\\x3A\\x20', r'^', http_header03, flags=re.I)
   pcrereferer = http_header03
   http_header03 = ""
  if re.search( r'(?<!\^)Referer\\x3A ', http_header03, re.I ):
   http_header03 = re.sub( r'(?<!\^)Referer\\x3A ', r'^', http_header03, flags=re.I)
   pcrereferer = http_header03
   http_header03 = ""
  if re.search( r'\^Referer\\x3A', http_header03, re.I ):
   http_header03 = re.sub( r'\^Referer\\x3A', r'^', http_header03, flags=re.I)
   pcrereferer = http_header03
   http_header03 = ""
  if re.search( r'(?<!\^)Referer\\x3A', http_header03, re.I ):
   http_header03 = re.sub( r'(?<!\^)Referer\\x3A', r'^', http_header03, flags=re.I)
   pcrereferer = http_header03
   http_header03 = ""
 if http_header13:
  if re.search( r'\^Referer\\x3A\\x20', http_header13, re.I ):
   http_header13 = re.sub( r'\^Referer\\x3A\\x20', r'^', http_header13, flags=re.I)
   pcrereferer = http_header13
   http_header13 = ""
  if re.search( r'\^Referer\\x3A ', http_header13, re.I ):
   http_header13 = re.sub( r'\^Referer\\x3A ', r'^', http_header13, flags=re.I)
   pcrereferer = http_header13
   http_header13 = ""
  if re.search( r'(?<!\^)Referer\\x3A\\x20', http_header13, re.I ):
   http_header13 = re.sub( r'(?<!\^)Referer\\x3A\\x20', r'^', http_header13, flags=re.I)
   pcrereferer = http_header13
   http_header13 = ""
  if re.search( r'(?<!\^)Referer\\x3A ', http_header13, re.I ):
   http_header13 = re.sub( r'(?<!\^)Referer\\x3A ', r'^', http_header13, flags=re.I)
   pcrereferer = http_header13
   http_header13 = ""
  if re.search( r'\^Referer\\x3A', http_header13, re.I ):
   http_header13 = re.sub( r'\^Referer\\x3A', r'^', http_header13, flags=re.I)
   pcrereferer = http_header13
   http_header13 = ""
  if re.search( r'(?<!\^)Referer\\x3A', http_header13, re.I ):
   http_header13 = re.sub( r'(?<!\^)Referer\\x3A', r'^', http_header13, flags=re.I)
   pcrereferer = http_header13
   http_header13 = ""
 if http_header23:
  if re.search( r'\^Referer\\x3A\\x20', http_header23, re.I ):
   http_header23 = re.sub( r'\^Referer\\x3A\\x20', r'^', http_header23, flags=re.I)
   pcrereferer = http_header23
   http_header23 = ""
  if re.search( r'\^Referer\\x3A ', http_header23, re.I ):
   http_header23 = re.sub( r'\^Referer\\x3A ', r'^', http_header23, flags=re.I)
   pcrereferer = http_header23
   http_header23 = ""
  if re.search( r'(?<!\^)Referer\\x3A\\x20', http_header23, re.I ):
   http_header23 = re.sub( r'(?<!\^)Referer\\x3A\\x20', r'^', http_header23, flags=re.I)
   pcrereferer = http_header23
   http_header23 = ""
  if re.search( r'(?<!\^)Referer\\x3A ', http_header23, re.I ):
   http_header23 = re.sub( r'(?<!\^)Referer\\x3A ', r'^', http_header23, flags=re.I)
   pcrereferer = http_header23
   http_header23 = ""
  if re.search( r'\^Referer\\x3A', http_header23, re.I ):
   http_header23 = re.sub( r'\^Referer\\x3A', r'^', http_header23, flags=re.I)
   pcrereferer = http_header23
   http_header23 = ""
  if re.search( r'(?<!\^)Referer\\x3A', http_header23, re.I ):
   http_header23 = re.sub( r'(?<!\^)Referer\\x3A', r'^', http_header23, flags=re.I)
   pcrereferer = http_header23
   http_header23 = ""
 if pcre_agent34:
  if re.search( r'\^Referer\\x3A\\x20', pcre_agent34, re.I ):
   pcre_agent34 = re.sub( r'\^Referer\\x3A\\x20', r'^', pcre_agent34, flags=re.I)
   pcrereferer = pcre_agent34
   pcre_agent34 = ""
  if re.search( r'\^Referer\\x3A ', pcre_agent34, re.I ):
   pcre_agent34 = re.sub( r'\^Referer\\x3A ', r'^', pcre_agent34, flags=re.I)
   pcrereferer = pcre_agent34
   pcre_agent34 = ""
  if re.search( r'(?<!\^)Referer\\x3A\\x20', pcre_agent34, re.I ):
   pcre_agent34 = re.sub( r'(?<!\^)Referer\\x3A\\x20', r'^', pcre_agent34, flags=re.I)
   pcrereferer = pcre_agent34
   pcre_agent34 = ""
  if re.search( r'(?<!\^)Referer\\x3A ', pcre_agent34, re.I ):
   pcre_agent34 = re.sub( r'(?<!\^)Referer\\x3A ', r'^', pcre_agent34, flags=re.I)
   pcrereferer = pcre_agent34
   pcre_agent34 = ""
  if re.search( r'\^Referer\\x3A', pcre_agent34, re.I ):
   pcre_agent34 = re.sub( r'\^Referer\\x3A', r'^', pcre_agent34, flags=re.I)
   pcre_agent34 = re.sub( r'(?!^)\\x0D\\x0A', r'$', pcre_agent34, flags=re.I)
   pcrereferer = pcre_agent34
   pcre_agent34 = ""
  if re.search( r'(?<!\^)Referer\\x3A', pcre_agent34, re.I ):
   pcre_agent34 = re.sub( r'(?<!\^)Referer\\x3A', r'^', pcre_agent34, flags=re.I)
   pcrereferer = pcre_agent34
   pcre_agent34 = ""
 if pcrereferer: pcrereferer = re.sub(  r'(?!^)\\x0D\\x0A', r'$', pcrereferer, flags=re.I)

 if pcrereferer and not re.search( r'\\x', pcrereferer ) and re.search( r'^\^', pcrereferer ) and not re.search( r'^\^\\\-\$$', pcrereferer ) and not re.search( r'\(\?\!', pcrereferer ):
  pcrereferer=re.sub( r'\\', r'', pcrereferer )
  pcrereferer=re.sub( r'^\^', r'', pcrereferer )
  pcrereferer=re.sub( r'\$$', r'', pcrereferer )
  httpreferer=pcrereferer
  pcrereferer=0

 if http_header03:
  if re.search( r'\\x0d\\x0aCookie\\x3A (?!$)', http_header03, re.I ):
   http_header03 = re.sub( r'\\x0d\\x0aCookie\\x3A (?!$)', r'^', http_header03, flags=re.I)
   http_cookie = http_header03
   http_header03 = ""
  if re.search( r'Cookie\\x3A (?!$)', http_header03, re.I ):
   http_header03 = re.sub( r'Cookie\\x3A (?!$)', r'^', http_header03, flags=re.I)
   http_cookie = http_header03
   http_header03 = ""
  if re.search( r'\\x0d\\x0aCookie\\x3A\\x20(?!$)', http_header03, re.I ):
   http_header03 = re.sub( r'\\x0d\\x0aCookie\\x3A\\x20(?!$)', r'^', http_header03, flags=re.I)
   http_cookie = http_header03
   http_header03 = ""
  if re.search( r'Cookie\\x3A\\x20(?!$)', http_header03, re.I ):
   http_header03 = re.sub( r'Cookie\\x3A\\x20(?!$)', r'^', http_header03, flags=re.I)
   http_cookie = http_header03
   http_header03 = ""
  if re.search( r'\\x0d\\x0aCookie\: (?!$)', http_header03, re.I ):
   http_header03 = re.sub( r'\\x0d\\x0aCookie\: (?!$)', r'^', http_header03, flags=re.I)
   http_cookie = http_header03
   http_header03 = ""
  if re.search( r'Cookie\: (?!$)', http_header03, re.I ):
   http_header03 = re.sub( r'Cookie\: (?!$)', r'^', http_header03, flags=re.I)
   http_cookie = http_header03
   http_header03 = ""
 if http_header13:
  if re.search( r'\\x0d\\x0aCookie\\x3A (?!$)', http_header13, re.I ):
   http_header13 = re.sub( r'\\x0d\\x0aCookie\\x3A (?!$)', r'^', http_header13, flags=re.I)
   http_cookie = http_header13
   http_header13 = ""
  if re.search( r'Cookie\\x3A (?!$)', http_header13, re.I ):
   http_header13 = re.sub( r'Cookie\\x3A (?!$)', r'^', http_header13, flags=re.I)
   http_cookie = http_header13
   http_header13 = ""
  if re.search( r'\\x0d\\x0aCookie\\x3A\\x20(?!$)', http_header13, re.I ):
   http_header13 = re.sub( r'\\x0d\\x0aCookie\\x3A\\x20(?!$)', r'^', http_header13, flags=re.I)
   http_cookie = http_header13
   http_header13 = ""
  if re.search( r'Cookie\\x3A\\x20(?!$)', http_header13, re.I ):
   http_header13 = re.sub( r'Cookie\\x3A\\x20(?!$)', r'^', http_header13, flags=re.I)
   http_cookie = http_header13
   http_header13 = ""
  if re.search( r'\\x0d\\x0aCookie\: (?!$)', http_header13, re.I ):
   http_header13 = re.sub( r'\\x0d\\x0aCookie\: (?!$)', r'^', http_header13, flags=re.I)
   http_cookie = http_header13
   http_header13 = ""
  if re.search( r'Cookie\: (?!$)', http_header13, re.I ):
   http_header13 = re.sub( r'Cookie\: (?!$)', r'^', http_header13, flags=re.I)
   http_cookie = http_header13
   http_header13 = ""
 if http_header23:
  if re.search( r'\\x0d\\x0aCookie\\x3A (?!$)', http_header23, re.I ):
   http_header23 = re.sub( r'\\x0d\\x0aCookie\\x3A (?!$)', r'^', http_header23, flags=re.I)
   http_cookie = http_header23
   http_header23 = ""
  if re.search( r'Cookie\\x3A (?!$)', http_header23, re.I ):
   http_header23 = re.sub( r'Cookie\\x3A (?!$)', r'^', http_header23, flags=re.I)
   http_cookie = http_header23
   http_header23 = ""
  if re.search( r'\\x0d\\x0aCookie\\x3A\\x20(?!$)', http_header23, re.I ):
   http_header23 = re.sub( r'\\x0d\\x0aCookie\\x3A\\x20(?!$)', r'^', http_header23, flags=re.I)
   http_cookie = http_header23
   http_header23 = ""
  if re.search( r'Cookie\\x3A\\x20(?!$)', http_header23, re.I ):
   http_header23 = re.sub( r'Cookie\\x3A\\x20(?!$)', r'^', http_header23, flags=re.I)
   http_cookie = http_header23
   http_header23 = ""
  if re.search( r'\\x0d\\x0aCookie\: (?!$)', http_header23, re.I ):
   http_header23 = re.sub( r'\\x0d\\x0aCookie\: (?!$)', r'^', http_header23, flags=re.I)
   http_cookie = http_header23
   http_header23 = ""
  if re.search( r'Cookie\: (?!$)', http_header23, re.I ):
   http_header23 = re.sub( r'Cookie\: (?!$)', r'^', http_header23, flags=re.I)
   http_cookie = http_header23
   http_header23 = ""
 if pcre_agent34:
  if re.search( r'\\x0d\\x0aCookie\\x3A (?!$)', pcre_agent34, re.I ):
   pcre_agent34 = re.sub( r'\\x0d\\x0aCookie\\x3A (?!$)', r'^', pcre_agent34, flags=re.I)
   http_cookie = pcre_agent34
   pcre_agent34 = ""
  if re.search( r'Cookie\\x3A (?!$)', pcre_agent34, re.I ):
   pcre_agent34 = re.sub( r'Cookie\\x3A (?!$)', r'^', pcre_agent34, flags=re.I)
   http_cookie = pcre_agent34
   pcre_agent34 = ""
  if re.search( r'\\x0d\\x0aCookie\\x3A\\x20(?!$)', pcre_agent34, re.I ):
   pcre_agent34 = re.sub( r'\\x0d\\x0aCookie\\x3A\\x20(?!$)', r'^', pcre_agent34, flags=re.I)
   http_cookie = pcre_agent34
   pcre_agent34 = ""
  if re.search( r'Cookie\\x3A\\x20(?!$)', pcre_agent34, re.I ):
   pcre_agent34 = re.sub( r'Cookie\\x3A\\x20(?!$)', r'^', pcre_agent34, flags=re.I)
   http_cookie = pcre_agent34
   pcre_agent34 = ""
  if re.search( r'\\x0d\\x0aCookie\: (?!$)', pcre_agent34, re.I ):
   pcre_agent34 = re.sub( r'\\x0d\\x0aCookie\: (?!$)', r'^', pcre_agent34, flags=re.I)
   http_cookie = pcre_agent34
   pcre_agent34 = ""
  if re.search( r'Cookie\: (?!$)', pcre_agent34, re.I ):
   pcre_agent34 = re.sub( r'Cookie\: (?!$)', r'^', pcre_agent34, flags=re.I)
   http_cookie = pcre_agent34
   pcre_agent34 = ""

 if http_header03: http_header03=re.sub(  r'(?!^)\\x0D\\x0A', r'$', http_header03, flags=re.I)
 if http_header13: http_header13=re.sub(  r'(?!^)\\x0D\\x0A', r'$', http_header13, flags=re.I)
 if http_header23: http_header23=re.sub(  r'(?!^)\\x0D\\x0A', r'$', http_header23, flags=re.I)
 if pcre_agent34: pcre_agent34=re.sub(  r'(?!^)\\x0D\\x0A', r'$', pcre_agent34, flags=re.I)
 if http_cookie: http_cookie=re.sub(  r'(?!^)\\x0D\\x0A', r'$', http_cookie, flags=re.I)

 if http_cookie and re.search( r'\\x', http_cookie ):
  if not cookiepcre: cookiepcre = http_cookie
  http_cookie = ""
 elif http_cookie and re.search( r'(?:\^|\$)', http_cookie ):
  if not cookiepcre: cookiepcre = http_cookie
  http_cookie=re.sub(  r'(?:\^|\$)', r'', http_cookie)
 elif http_cookie and re.search( r'\\', http_cookie ):
  http_cookie=re.sub(  r'\\', r'', http_cookie)

 if pcre_agent34:
  pcre_agent34 = re.sub( r'\^\[\^\\r\\n\]\+\?', r'', pcre_agent34, flags=re.I )
  pcre_agent34 = re.sub( r'\^\[\^\\r\\n\]\*\?', r'', pcre_agent34, flags=re.I )
  pcre_agent34 = re.sub( r'\^\[\^\\r\\n\]\+', r'', pcre_agent34, flags=re.I )
  pcre_agent34 = re.sub( r'\^\[\^\\r\\n\]\*', r'', pcre_agent34, flags=re.I )
  pcre_agent34 = re.sub( r'\^\[\^\\n\]\+\?', r'', pcre_agent34, flags=re.I )
  pcre_agent34 = re.sub( r'\^\[\^\\n\]\*\?', r'', pcre_agent34, flags=re.I )
  pcre_agent34 = re.sub( r'\^\[\^\\n\]\+', r'', pcre_agent34, flags=re.I )
  pcre_agent34 = re.sub( r'\^\[\^\\n\]\*', r'', pcre_agent34, flags=re.I )

 if pcre_uri33:
  pcre_uri33 = re.sub( r'^\^\\\\/', r'^(?:https?\\:\\/\\/)?[^\\/]*?\\\/', pcre_uri33, flags=re.I )
  pcre_uri33 = re.sub( r'^\^\\\x2F', r'^(?:https?\\:\\/\\/)?[^\\/]*?\\\x2F', pcre_uri33, flags=re.I )

 #if( $pcre_agent34 && $http_header03 && ( $pcre_agent34 =~ /^\^\[\^(?:\\r)?\\n(?:\\r)?\]\+(.*)$/ ) && ( $http_header03 eq $1 ) ) { $okremiseazeropcreagent34=1 }
 #if( $pcre_agent34 && $http_header13 && ( $pcre_agent34 =~ /^\^\[\^(?:\\r)?\\n(?:\\r)?\]\+(.*)$/ ) && ( $http_header13 eq $1 ) ) { $okremiseazeropcreagent34=1 }
 #if( $pcre_agent34 && $http_header23 && ( $pcre_agent34 =~ /^\^\[\^(?:\\r)?\\n(?:\\r)?\]\+(.*)$/ ) && ( $http_header23 eq $1 ) ) { $okremiseazeropcreagent34=1 }
 okremiseazeropcreagent34=0
 if pcre_agent34 and http_header03 and re.search( r'^\^\[\^(?:\\r)?\\n(?:\\r)?\]\+'+http_header03+'$', pcre_agent34 ):
  okremiseazeropcreagent34=1
 if pcre_agent34 and http_header13 and re.search( r'^\^\[\^(?:\\r)?\\n(?:\\r)?\]\+'+http_header13+'$', pcre_agent34 ):
  okremiseazeropcreagent34=1
 if pcre_agent34 and http_header23 and re.search( r'^\^\[\^(?:\\r)?\\n(?:\\r)?\]\+'+http_header23+'$', pcre_agent34 ):
  okremiseazeropcreagent34=1

 # http_user_agent short
 if http_header03 and http_header13 and http_header23 and ( http_header03.__len__() >= ( http_header13.__len__() or http_header23.__len__() ) ):
  httpagentshort = http_header03
 elif http_header03 and http_header13 and http_header23 and ( http_header13.__len__() >= ( http_header03.__len__() or http_header23.__len__() ) ):
  httpagentshort = http_header13
 elif http_header03 and http_header13 and http_header23 and ( http_header23.__len__() >= ( http_header03.__len__() or http_header13.__len__() ) ):
  httpagentshort = http_header23
 elif http_header03 and http_header13 and not http_header23 and ( http_header03.__len__() >= http_header13.__len__() ):
  httpagentshort = http_header03
 elif http_header03 and http_header13 and not http_header23 and ( http_header13.__len__() >= http_header03.__len__() ):
  httpagentshort = http_header13
 elif http_header03 and http_header23 and not http_header13 and ( http_header03.__len__() >= http_header23.__len__() ):
  httpagentshort = http_header03
 elif http_header03 and http_header23 and not http_header13 and ( http_header23.__len__() >= http_header03.__len__() ):
  httpagentshort = http_header23
 elif http_header13 and http_header23 and not http_header03 and ( http_header13.__len__() >= http_header23.__len__() ):
  httpagentshort = http_header13
 elif http_header13 and http_header23 and not http_header03 and ( http_header23.__len__() >= http_header13.__len__() ):
  httpagentshort = http_header23
 elif http_header03 and not http_header13 and not http_header23:
  httpagentshort = http_header03
 elif http_header13 and not http_header03 and not http_header23:
  httpagentshort = http_header13
 elif http_header23 and not http_header03 and not http_header13:
  httpagentshort = http_header23

 if httpagentshort:
  httpagentshort = re.sub( r"\\x(..)", function_replacement_http_agent_short, httpagentshort)
  httpagentshort = re.sub( r'(?:\\(?!$)(?:x[a-f0-9]{2})?|\^|\$)', r'', httpagentshort)

 if pcre_agent34 and http_header03 and ( http_header03.lower() in pcre_agent34.lower() ):
  http_header03=""
  if debug1: print("ok trouvé grep3a")
 elif pcre_agent34 and http_header03 and ( '&' in http_header03 ):
  http_header03 = re.sub( r'\&', r'\\x26', http_header03 )
  if http_header03.lower() in pcre_agent34.lower():
   http_header03=""
   if debug1: print("ok trouvé grep3b")
 elif pcre_agent34 and http_header03 and ( '=' in http_header03 ):
  http_header03 = re.sub( r'\=', r'\\x3D', http_header03 )
  if http_header03.lower() in pcre_agent34.lower():
   http_header03=""
   if debug1: print("ok trouvé grep3c")
 if pcre_uri33 and http_uri08 and ( http_uri08.lower() in pcre_uri33.lower() ):
  http_uri08=""
  if debug1: print("ok trouvé grep8a")
 elif pcre_uri33 and http_uri08 and ( '&' in http_uri08 ):
  http_uri08 = re.sub( r'\&', r'\\x26', http_uri08 )
  if http_uri08.lower() in pcre_uri33.lower():
   http_uri08=""
   if debug1: print("ok trouvé grep8b")
 elif pcre_uri33 and http_uri08 and ( '=' in http_uri08 ):
  http_uri08 = re.sub( r'\=', r'\\x3D', http_uri08 )
  if http_uri08.lower() in pcre_uri33.lower():
   http_uri08=""
   if debug1: print("ok trouvé grep8c")
 if pcre_agent34 and http_header13 and ( http_header13.lower() in pcre_agent34.lower() ):
  http_header13=""
  if debug1: print("ok trouvé grep13a")
 elif pcre_agent34 and http_header13 and ( '&' in http_header13 ):
  http_header13 = re.sub( r'\&', r'\\x26', http_header13 )
  if http_header13.lower() in pcre_agent34.lower():
   http_header13=""
   if debug1: print("ok trouvé grep13b")
 elif pcre_agent34 and http_header13 and ( '=' in http_header13 ):
  http_header13 = re.sub( r'\=', r'\\x3D', http_header13 )
  if http_header13.lower() in pcre_agent34.lower():
   http_header13=""
   if debug1: print("ok trouvé grep13c")
 if pcre_uri33 and http_uri18 and ( http_uri18.lower() in pcre_uri33.lower() ):
  http_uri18=""
  if debug1: print("ok trouvé grep18a")
 elif pcre_uri33 and http_uri18 and ( '&' in http_uri18 ):
  http_uri18 = re.sub( r'\&', r'\\x26', http_uri18 )
  if http_uri18.lower() in pcre_uri33.lower():
   http_uri18=""
   if debug1: print("ok trouvé grep18b")
 elif pcre_uri33 and http_uri18 and ( '=' in http_uri18 ):
  http_uri18 = re.sub( r'\=', r'\\x3D', http_uri18 )
  if http_uri18.lower() in pcre_uri33.lower():
   http_uri18=""
   if debug1: print("ok trouvé grep18c")
 if pcre_agent34 and http_header23 and ( http_header23.lower() in pcre_agent34.lower() ):
  http_header23=""
  if debug1: print("ok trouvé grep23a")
 elif pcre_agent34 and http_header23 and ( '&' in http_header23 ):
  http_header23 = re.sub( r'\&', r'\\x26', http_header23 )
  if http_header23.lower() in pcre_agent34.lower():
   http_header23=""
   if debug1: print("ok trouvé grep23b")
 elif pcre_agent34 and http_header23 and ( '=' in http_header23 ):
  http_header23 = re.sub( r'\=', r'\\x3D', http_header23 )
  if http_header23.lower() in pcre_agent34.lower():
   http_header23=""
   if debug1: print("ok trouvé grep23c")
 if pcre_uri33 and http_uri28 and ( http_uri28.lower() in pcre_uri33.lower() ):
  http_uri28=""
  if debug1: print("ok trouvé grep28a")
 elif pcre_uri33 and http_uri28 and ( '&' in http_uri28 ):
  http_uri28 = re.sub( r'\&', r'\\x26', http_uri28 )
  if http_uri28.lower() in pcre_uri33.lower():
   http_uri28=""
   if debug1: print("ok trouvé grep28b")
 elif pcre_uri33 and http_uri28 and ( '=' in http_uri28 ):
  http_uri28 = re.sub( r'\=', r'\\x3D', http_uri28 )
  if http_uri28.lower() in pcre_uri33.lower():
   http_uri28=""
   if debug1: print("ok trouvé grep28c")

 # one header
 if http_header03 and not http_header13 and not http_header23 and not pcre_agent34 and re.search( r'(?:\\|\^|\$)', http_header03 ): httppcreagent = http_header03
 if http_header13 and not http_header03 and not http_header23 and not pcre_agent34 and re.search( r'(?:\\|\^|\$)', http_header13 ): httppcreagent = http_header13
 if http_header23 and not http_header13 and not http_header03 and not pcre_agent34 and re.search( r'(?:\\|\^|\$)', http_header23 ): httppcreagent = http_header23
 if pcre_agent34 and not http_header03 and not http_header13 and not http_header23: httppcreagent = pcre_agent34

 # one uri
 if pcre_uri33 and not http_uri08 and not http_uri18: abc1 = pcre_uri33

 # two headers
 if http_header03 and http_header13 and not http_header23 and not pcre_agent34 and ( distance14 or distance15 or distance16 or distance17 ):
  httppcreagent = '(?:'+http_header03+'.*?'+http_header13+')'
 elif http_header03 and http_header13 and not http_header23 and not pcre_agent34 and not ( distance14 or distance15 or distance16 or distance17 ):
  httppcreagent = '(?:'+http_header03+'.*?'+http_header13+'|'+http_header13+'.*?'+http_header03+')'
 elif http_header03 and not http_header13 and http_header23 and not pcre_agent34 and ( distance14 or distance15 or distance16 or distance17 ):
  httppcreagent = '(?:'+http_header03+'.*?'+http_header23+')'
 elif http_header03 and not http_header13 and http_header23 and not pcre_agent34 and not ( distance14 or distance15 or distance16 or distance17 ):
  httppcreagent = '(?:'+http_header03+'.*?'+http_header23+'|'+http_header23+'.*?'+http_header03+')'
 elif http_header03 and not http_header13 and not http_header23 and pcre_agent34 and ( distance14 or distance15 or distance16 or distance17 ):
  httppcreagent = '(?:'+http_header03+'.*?'+pcre_agent34+')'
 elif http_header03 and not http_header13 and not http_header23 and pcre_agent34 and not ( distance14 or distance15 or distance16 or distance17 ):
  httppcreagent = '(?:'+http_header03+'.*?'+pcre_agent34+'|'+pcre_agent34+'.*?'+http_header03+')'

 # two uri
 if http_uri08 and http_uri18 and not http_uri28 and not pcre_uri33 and not ( re.search( r'\\x|^\^|\$$', http_uri08 ) or re.search( r'\\x|^\^|\$$', http_uri18 ) ):
  http_uri08 = re.sub( r'\\(?!x)', r'', http_uri08)
  http_uri18 = re.sub( r'\\(?!x)', r'', http_uri18)
  if re.search( r'\\x|^\^|\$$', http_uri08 ):
   tableauuri1=0
  elif re.search( r'\\x|^\^|\$$', http_uri18 ):
   tableauuri1=0
  else:
   tableauuri1 = ( http_uri08.lower(), http_uri18.lower() )
 elif http_uri08 and http_uri18 and not http_uri28 and not pcre_uri33: abc1 = '(?:'+http_uri08+'.*?'+http_uri18+'|'+http_uri18+'.*?'+http_uri08+')'

 # three headers
 if ( distance14 or distance15 or distance16 or distance17 ) and ( distance24 or distance25 or distance26 or distance27 ):
  if http_header03 and http_header13 and http_header23 and not pcre_agent34: httppcreagent = '(?:'+http_header03+'.*'+http_header13+'.*'+http_header23+')'

 elif not ( distance14 or distance15 or distance16 or distance17 ) and not ( distance24 or distance25 or distance26 or distance27 ):
  if http_header03 and http_header13 and http_header23 and not pcre_agent34: httppcreagent = '(?:'+http_header03+'.*'+http_header13+'.*'+http_header23+'|'+http_header03+'.*'+http_header23+'.*'+http_header13+'|'+http_header23+'.*'+http_header03+'.*'+http_header13+'|'+http_header23+'.*'+http_header13+'.*'+http_header03+')'
  if http_header03 and http_header13 and pcre_agent34 and not http_header23: httppcreagent = '(?:'+http_header03+'.*'+http_header13+'.*'+pcre_agent34+'|'+http_header03+'.*'+pcre_agent34+'.*'+http_header13+'|'+pcre_agent34+'.*'+http_header03+'.*'+http_header13+'|'+pcre_agent34+'.*'+http_header13+'.*'+http_header03+')'

 # three uri
 if http_uri08 and http_uri18 and http_uri28 and pcre_uri33 and not ( re.search( r'\\x|^\^|\$$', http_uri08 ) or re.search( r'\\x|^\^|\$$', http_uri18 ) or re.search( r'\\x|^\^|\$$', http_uri28 ) ):
  http_uri08 = re.sub( r'\\(?!x)', r'', http_uri08)
  http_uri18 = re.sub( r'\\(?!x)', r'', http_uri18)
  http_uri28 = re.sub( r'\\(?!x)', r'', http_uri28)
  if re.search( r'\\x|^\^|\$$', http_uri08 ):
   tableauuri1=0
  elif re.search( r'\\x|^\^|\$$', http_uri18 ):
   tableauuri1=0
  elif re.search( r'\\x|^\^|\$$', http_uri28 ):
   tableauuri1=0
  else:
   tableauuri1 = ( http_uri08.lower(), http_uri18.lower(), http_uri28.lower() )
 elif http_uri08 and http_uri18 and http_uri28 and not pcre_uri33: abc1 = '(?:'+http_uri08+'.*'+http_uri18+'.*'+http_uri28+'|'+http_uri08+'.*'+http_uri28+'.*'+http_uri18+'|'+http_uri28+'.*'+http_uri18+'.*'+http_uri08+'|'+http_uri18+'.*'+http_uri28+'.*'+http_uri08+')'

 # four headers
 if http_header03 and http_header13 and http_header23 and pcre_agent34:
  httppcreagent= '(?:'+http_header03+'.*'+http_header13+'.*'+http_header23+'.*'+pcre_agent34+'|'+http_header03+'.*'+http_header13+'.*'+pcre_agent34+'.*'+http_header23+'|'+http_header03+'.*'+http_header23+'.*'+http_header13+'.*'+pcre_agent34+'|'+http_header03+'.*'+http_header23+'.*'+pcre_agent34+'.*'+http_header13+'|'+http_header13+'.*'+http_header23+'.*'+pcre_agent34+'.*'+http_header03+'|'+http_header13+'.*'+http_header23+'.*'+http_header03+'.*'+pcre_agent34+'|'+http_header13+'.*'+http_header03+'.*'+http_header23+'.*'+pcre_agent34+'|'+http_header13+'.*'+http_header03+'.*'+pcre_agent34+'.*'+http_header23+'|'+http_header23+'.*'+http_header03+'.*'+http_header13+'.*'+pcre_agent34+'|'+http_header23+'.*'+http_header03+'.*'+pcre_agent34+'.*'+http_header13+'|'+http_header23+'.*'+http_header13+'.*'+pcre_agent34+'.*'+http_header03+'|'+http_header23+'.*'+http_header13+'.*'+http_header03+'.*'+pcre_agent34+'|'+pcre_agent34+'.*'+http_header03+'.*'+http_header13+'.*'+http_header23+'|'+pcre_agent34+'.*'+http_header03+'.*'+http_header23+'.*'+http_header13+'|'+pcre_agent34+'.*'+http_header23+'.*'+http_header03+'.*'+http_header13+'|'+pcre_agent34+'.*'+http_header23+'.*'+http_header13+'.*'+http_header03+')'

 # four uri
 if http_uri08 and http_uri18 and http_uri28 and pcre_uri33:
  abc1= '(?:'+http_uri08+'.*'+http_uri18+'.*'+http_uri28+'.*'+pcre_uri33+'|'+http_uri08+'.*'+http_uri18+'.*'+pcre_uri33+'.*'+http_uri28+'|'+http_uri08+'.*'+http_uri28+'.*'+http_uri18+'.*'+pcre_uri33+'|'+http_uri08+'.*'+http_uri28+'.*'+pcre_uri33+'.*'+http_uri18+'|'+http_uri18+'.*'+http_uri28+'.*'+pcre_uri33+'.*'+http_uri08+'|'+http_uri18+'.*'+http_uri28+'.*'+http_uri08+'.*'+pcre_uri33+'|'+http_uri18+'.*'+http_uri08+'.*'+http_uri28+'.*'+pcre_uri33+'|'+http_uri18+'.*'+http_uri08+'.*'+pcre_uri33+'.*'+http_uri28+'|'+http_uri28+'.*'+http_uri08+'.*'+http_uri18+'.*'+pcre_uri33+'|'+http_uri28+'.*'+http_uri08+'.*'+pcre_uri33+'.*'+http_uri18+'|'+http_uri28+'.*'+http_uri18+'.*'+pcre_uri33+'.*'+http_uri08+'|'+http_uri28+'.*'+http_uri18+'.*'+http_uri08+'.*'+pcre_uri33+'|'+pcre_uri33+'.*'+http_uri08+'.*'+http_uri18+'.*'+http_uri28+'|'+pcre_uri33+'.*'+http_uri08+'.*'+http_uri28+'.*'+http_uri18+'|'+pcre_uri33+'.*'+http_uri28+'.*'+http_uri08+'.*'+http_uri18+'|'+pcre_uri33+'.*'+http_uri28+'.*'+http_uri18+'.*'+http_uri08+')'

  if okremiseazeropcreagent34: httppcreagent=0

 # uri:
 abc1_nocase=0
 if http_urifast14:   abc1_nocase=http_urifast14
 if http_urinocase12: abc1_nocase=http_urinocase12
 if http_urifast18:   abc1_nocase=http_urifast18
 if http_urinocase15: abc1_nocase=http_urinocase15
 if http_urifast32:   abc1_nocase=http_urifast32
 if http_urinocase25: abc1_nocase=http_urinocase25
 if http_urifast36:   abc1_nocase=http_urifast36
 if http_urinocase28: abc1_nocase=http_urinocase28
 if http_urifast50:   abc1_nocase=http_urifast50
 if http_urinocase39: abc1_nocase=http_urinocase39
 if http_urifast54:   abc1_nocase=http_urifast54
 if http_urinocase42: abc1_nocase=http_urinocase42

 # header + cookie:
 httppcreagent_nocase=0;
 http_cookie_nocase=0
 if http_headerfast5:    httppcreagent_nocase=http_headerfast5;    http_cookie_nocase=http_headerfast5;
 if http_headernocase5:  httppcreagent_nocase=http_headernocase5;  http_cookie_nocase=http_headernocase5;
 if http_headerfast9:    httppcreagent_nocase=http_headerfast9;    http_cookie_nocase=http_headerfast9;
 if http_headernocase8:  httppcreagent_nocase=http_headernocase8;  http_cookie_nocase=http_headernocase8;
 if http_headerfast23:   httppcreagent_nocase=http_headerfast23;   http_cookie_nocase=http_headerfast23;
 if http_headernocase19: httppcreagent_nocase=http_headernocase19; http_cookie_nocase=http_headernocase19;
 if http_headerfast27:   httppcreagent_nocase=http_headerfast27;   http_cookie_nocase=http_headerfast27;
 if http_headernocase22: httppcreagent_nocase=http_headernocase22; http_cookie_nocase=http_headernocase22;
 if http_headerfast41:   httppcreagent_nocase=http_headerfast41;   http_cookie_nocase=http_headerfast41;
 if http_headernocase32: httppcreagent_nocase=http_headernocase32; http_cookie_nocase=http_headernocase32;
 if http_headerfast45:   httppcreagent_nocase=http_headerfast45;   http_cookie_nocase=http_headerfast45;
 if http_headernocase35: httppcreagent_nocase=http_headernocase35; http_cookie_nocase=http_headernocase35;

 if httpagentshort and httppcreagent:
  tempopcreagent = httppcreagent
  tempopcreagent = re.sub( r'\\(?!$)(?!x[a-f0-9]{2})', r'', tempopcreagent )
  if httpagentshort == tempopcreagent:
   if debug1: print("tempopcreagent: "+tempopcreagent)
   httppcreagent=0
   tempopcreagent=0

 if debug1 and httpuricourt:   print("httpuricourt4: "+etmsg1+", "+httpuricourt.lower())
 if debug1 and tableauuri1:    print("httpurilong4: "+etmsg1+", "+str(tableauuri1))
 if debug1 and abc1:           print("tableaupcreuri4: "+etmsg1+", "+str((abc1, abc1_nocase)))
 if debug1 and httppcreagent:  print("tableaupcreagent4: "+etmsg1+", "+str((httppcreagent, httppcreagent_nocase)))
 if debug1 and httpagentshort: print("httpagentshort4: "+etmsg1+", "+httpagentshort.lower())
 if debug1 and http_method2:   print("tableauhttpmethod4: "+etmsg1+", "+str((http_method2, http_methodnocase3)))
 if debug1 and httpreferer:    print("httpreferer4: "+etmsg1+", "+httpreferer.lower())
 if debug1 and pcrereferer:    print("tableaupcrereferer4: "+etmsg1+", "+pcrereferer)
 if debug1 and http_cookie:    print("tableauhttpcookie4: "+etmsg1+", "+str((http_cookie, http_cookie_nocase)))
 if debug1 and cookiepcre:     print("tableaupcrecookie4: "+etmsg1+", "+cookiepcre)

 if httpuricourt:   dict[(etmsg1, 'httpuricourt')] = httpuricourt.lower()
 if httpagentshort: dict[(etmsg1, 'httpagentshort')] = httpagentshort.lower()
 if http_method2:   dict[(etmsg1, 'httpmethod')] = (http_method2, http_methodnocase3)
 if httpreferer:    dict[(etmsg1, 'httpreferer')] = httpreferer.lower()
 if pcrereferer:    dict[(etmsg1, 'pcrereferer')] = pcrereferer
 if abc1:           dict[(etmsg1, 'pcreuri')] = (abc1, abc1_nocase)
 if httppcreagent:  dict[(etmsg1, 'pcreagent')] = (httppcreagent, httppcreagent_nocase)
 if tableauuri1:    dict[(etmsg1, 'httpurilong')] = tableauuri1
 if http_cookie:    dict[(etmsg1, 'httpcookie')] = (http_cookie, http_cookie_nocase)
 if cookiepcre:     dict[(etmsg1, 'pcrecookie')] = cookiepcre

 return; # function_match_http_header()

#######################################################################################

def function_match_http_cookie( lineet ):
 if debug1: print("brut5: "+lineet)
 etmsg1 = match_http_cookie2.group(1)
 http_method2 = 0
 http_methodnocase3 = 0
 http_method2 = match_http_cookie2.group(2)
 http_methodnocase3 = match_http_cookie2.group(3)
 http_uri03 = match_http_cookie2.group(4)
 http_urinocase5 = match_http_cookie2.group(6)
 http_urinocase8 = match_http_cookie2.group(10)
 http_cookie = match_http_cookie2.group(13)
 http_cookienocase12 = match_http_cookie2.group(15)
 http_cookienocase15 = match_http_cookie2.group(19)
 pcre_uri13 = match_http_cookie2.group(22)
 cookiepcre = match_http_cookie2.group(23)

 # check what is http_uri best length ?
 httpuricourt=0
 if http_uri03: httpuricourt=http_uri03

 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_uri03 ) # (
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_uri03 ) # )
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_uri03 ) # *
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_uri03 ) # +
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_uri03 ) # -
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_uri03 ) # .
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_uri03 ) # /
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_uri03 ) # ?
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_uri03 ) # [
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_uri03 ) # ]
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_uri03 ) # ^
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_uri03 ) # {
 if http_uri03: http_uri03 = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_uri03 ) # }
 if http_cookie: http_cookie = re.sub( r'(?<!\x5C)\x28', '\x5C\x28', http_cookie ) # (
 if http_cookie: http_cookie = re.sub( r'(?<!\x5C)\x29', '\x5C\x29', http_cookie ) # )
 if http_cookie: http_cookie = re.sub( r'(?<!\x5C)\x2A', '\x5C\x2A', http_cookie ) # *
 if http_cookie: http_cookie = re.sub( r'(?<!\x5C)\x2B', '\x5C\x2B', http_cookie ) # +
 if http_cookie: http_cookie = re.sub( r'(?<!\x5C)\x2D', '\x5C\x2D', http_cookie ) # -
 if http_cookie: http_cookie = re.sub( r'(?<!\x5C)\x2E', '\x5C\x2E', http_cookie ) # .
 if http_cookie: http_cookie = re.sub( r'(?<!\x5C)\x2F', '\x5C\x2F', http_cookie ) # /
 if http_cookie: http_cookie = re.sub( r'(?<!\x5C)\x3F', '\x5C\x3F', http_cookie ) # ?
 if http_cookie: http_cookie = re.sub( r'(?<!\x5C)\x5B', '\x5C\x5B', http_cookie ) # [
 if http_cookie: http_cookie = re.sub( r'(?<!\x5C)\x5D', '\x5C\x5D', http_cookie ) # ]
 if http_cookie: http_cookie = re.sub( r'(?<!\x5C)\x5E', '\x5C\x5E', http_cookie ) # ^
 if http_cookie: http_cookie = re.sub( r'(?<!\x5C)\x7B', '\x5C\x7B', http_cookie ) # {
 if http_cookie: http_cookie = re.sub( r'(?<!\x5C)\x7D', '\x5C\x7D', http_cookie ) # }
 #$pcre_uri13 =~ s/(?<!\x5C)\x24//g         if $pcre_uri13; # $

 if http_uri03: http_uri03 = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_uri03)
 if http_cookie: http_cookie = re.sub( r"(?<!\x5C)\|(.*?)\|", function_replacement_http_uri, http_cookie)
 # ne pas faire d'echappement sur la pcre ($pcre_uri13)

 abc1=0
 cookie=0
 if http_cookie:
  if re.search( r'\\x0d\\x0aCookie\\x3A (?!$)', http_cookie, re.I ):
   http_cookie = re.sub( r'\\x0d\\x0aCookie\\x3A (?!$)', r'^', http_cookie, flags=re.I)
   #cookie = http_cookie
   #http_cookie = ""
  if re.search( r'Cookie\\x3A (?!$)', http_cookie, re.I ):
   http_cookie = re.sub( r'Cookie\\x3A (?!$)', r'^', http_cookie, flags=re.I)
   #cookie = http_cookie
   #http_cookie = ""
  if re.search( r'\\x0d\\x0aCookie\\x3A\\x20(?!$)', http_cookie, re.I ):
   http_cookie = re.sub( r'\\x0d\\x0aCookie\\x3A\\x20(?!$)', r'^', http_cookie, flags=re.I)
   #cookie = http_cookie
   #http_cookie = ""
  if re.search( r'Cookie\\x3A\\x20(?!$)', http_cookie, re.I ):
   http_cookie = re.sub( r'Cookie\\x3A\\x20(?!$)', r'^', http_cookie, flags=re.I)
   #cookie = http_cookie
   #http_cookie = ""
  if re.search( r'\\x0d\\x0aCookie\: (?!$)', http_cookie, re.I ):
   http_cookie = re.sub( r'\\x0d\\x0aCookie\: (?!$)', r'^', http_cookie, flags=re.I)
   #cookie = http_cookie
   #http_cookie = ""
  if re.search( r'Cookie\: (?!$)', http_cookie, re.I ):
   http_cookie = re.sub( r'Cookie\: (?!$)', r'^', http_cookie, flags=re.I)
   #cookie = http_cookie
   #http_cookie = ""
 if http_cookie: http_cookie=re.sub(  r'(?!^)\\x0D\\x0A', r'$', http_cookie, flags=re.I)

 if http_cookie and re.search( r'\\x', http_cookie ):
  if not cookiepcre: cookiepcre = http_cookie
  http_cookie = ""
 elif http_cookie and re.search( r'(?:\^|\$)', http_cookie ):
  if not cookiepcre: cookiepcre = http_cookie
  http_cookie=re.sub(  r'(?:\^|\$)', r'', http_cookie)
 elif http_cookie and re.search( r'\\', http_cookie ):
  http_cookie=re.sub(  r'\\', r'', http_cookie)

 if pcre_uri13:
  pcre_uri13 = re.sub( r'^\^\\\\/', r'^(?:https?\\:\\/\\/)?[^\\/]*?\\\/', pcre_uri13, flags=re.I )
  pcre_uri13 = re.sub( r'^\^\\\x2F', r'^(?:https?\\:\\/\\/)?[^\\/]*?\\\x2F', pcre_uri13, flags=re.I )

 if pcre_uri13 and http_uri03 and ( http_uri03.lower() in pcre_uri13.lower() ):
  http_uri03=""
  if debug1: print("ok trouvé grep3a")
 elif pcre_uri13 and http_uri03 and ( '&' in http_uri03 ):
  http_uri03 = re.sub( r'\&', r'\\x26', http_uri03 )
  if http_uri03.lower() in pcre_uri13.lower():
   http_uri03=""
   if debug1: print("ok trouvé grep3b")
 elif pcre_uri13 and http_uri03 and ( '=' in http_uri03 ):
  http_uri03 = re.sub( r'\=', r'\\x3D', http_uri03 )
  if http_uri03.lower() in pcre_uri13.lower():
   http_uri03=""
   if debug1: print("ok trouvé grep3c")

 if http_uri03 and not pcre_uri13: abc1 = http_uri03
 if pcre_uri13 and not http_uri03: abc1 = pcre_uri13
 if http_uri03 and pcre_uri13: abc1= '(?:'+http_uri03+'.*?'+pcre_uri13+'|'+pcre_uri13+'.*?'+http_uri03+')'

 if httpuricourt and abc1:
  tempopcreuri = abc1
  tempopcreuri = re.sub( r'\\(?!$)(?!x[a-f0-9]{2})', r'', tempopcreuri )
  if httpuricourt == tempopcreuri:
   if debug1: print("tempopcreuri: "+tempopcreuri)
   abc1=0
   tempopcreuri=0

 abc1_nocase=0

 # cookie:
 http_cookie_nocase=0
 if http_cookienocase12: http_cookie_nocase=http_cookienocase12
 if http_cookienocase15: http_cookie_nocase=http_cookienocase15

 if debug1 and httpuricourt:   print("httpuricourt5: "+etmsg1+", "+httpuricourt.lower())
 if debug1 and abc1:           print("tableaupcreuri5: "+etmsg1+", "+str((abc1, abc1_nocase)))
 if debug1 and http_method2:   print("tableauhttpmethod5: "+etmsg1+", "+str((http_method2, http_methodnocase3)))
 if debug1 and http_cookie:    print("tableauhttpcookie5: "+etmsg1+", "+str((http_cookie, http_cookie_nocase)))
 if debug1 and cookiepcre:     print("tableaupcrecookie5: "+etmsg1+", "+cookiepcre)

 if httpuricourt:   dict[(etmsg1, 'httpuricourt')] = httpuricourt.lower()
 if abc1:           dict[(etmsg1, 'pcreuri')] = (abc1, abc1_nocase)
 if http_method2:   dict[(etmsg1, 'httpmethod')] = (http_method2, http_methodnocase3)
 if http_cookie:    dict[(etmsg1, 'httpcookie')] = (http_cookie, http_cookie_nocase)
 if cookiepcre:     dict[(etmsg1, 'pcrecookie')] = cookiepcre

 if http_cookie: http_cookie = ""
 if cookiepcre:  cookiepcre = ""

 return; # function_match_http_cookie()

#######################################################################################

def function_match_ip( lineet ):
 if debug1: print("brut6: "+lineet)
 etmsg1 = match_ip2.group(2)
 remote_ip = match_ip2.group(1)

 if debug1 and remote_ip:   print("remoteip6: "+etmsg1+", "+remote_ip)

 if remote_ip:   dict[(etmsg1, 'remoteip')] = remote_ip

 if remote_ip: remote_ip = ""

 return; # function_match_ip()

#######################################################################################

for lineet in fileemergingthreats:
 if sys.version_info>=(3,):
  lineet = bytes.decode( lineet ) # new Python v3
 lineet = lineet.rstrip('\r\n')
 match_http_uri2 = match_http_uri1.match( lineet )
 match_uricontent2 = match_uricontent1.match( lineet )
 match_uriheader2 = match_uriheader1.match( lineet )
 match_http_header2 = match_http_header1.match( lineet )
 match_http_cookie2 = match_http_cookie1.match( lineet )
 match_ip2 = match_ip1.match( lineet )

 # nothing on idle lineet or commented lineet
 if re.match( r'^(?:$|#)', lineet):
  next
 # nothing on wrong side rules
 elif re.match( r'^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+\S+\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*flow\:\s*(?:to_client\s*\,|from_server\s*\,)?established(?:\s*\,\s*to_client|\s*\,\s*from_server)?\;', lineet):
  next
 # nothing on icmp rules
 #elif re.match( r'^\s*alert\s+(?:icmp|ip)\s+\S+\s+\S+\s+\-\>\s+\S+\s+\S+\s+', lineet):
 elif re.match( r'^\s*alert\s+icmp\s+\S+\s+\S+\s+\-\>\s+\S+\s+\S+\s+', lineet):
  next
 # nothing on two directions rules
 elif re.match( r'^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\<\>\s+\S+\s+\S+\s+', lineet):
  next
 # nothing on rule contains http_client_body
 elif re.search( r'\bhttp_client_body\;', lineet):
  next

 # begin http_uri
 elif match_http_uri2:
  function_match_http_uri( lineet )

 # begin uricontent
 elif match_uricontent2:
  function_match_uricontent( lineet )

 # begin http_uri followed by a http_header
 elif match_uriheader2:
  function_match_uriheader( lineet )

 # begin http_header
 elif match_http_header2:
  function_match_http_header( lineet )

 # begin http_uri followed by http_cookie
 elif match_http_cookie2:
  function_match_http_cookie( lineet )

 elif match_ip2:
  function_match_ip( lineet )

 else:
  if debug1: print("erreur parsing signature: "+lineet)

fileemergingthreats.close()

####################################################################################################
if debug1: print("####################################################################################")

def function_logsandsearch( looplogs):
 looplogs = looplogs.strip('\n')
 output_escape = looplogs
 #$output_escape = printable($_);
 if debug2: print("rawproxy: "+output_escape)

 timestamp_central=0; server_hostname_ip=0; timestamp_unix=0; client_hostname_ip=0; client_username=0; http_reply_code=0; client_http_method=0; client_http_uri=0; web_hostname_ip=0; client_http_useragent=0; client_http_referer=0; client_http_cookie=0; server_remote_ip=0;

 squiddefault2 = squiddefault1.search( output_escape )
 squidua2 = squidua1.search( output_escape )
 apache2 = apache1.search( output_escape )
 tmg2 = tmg1.search( output_escape )
 bluecoat1a = bluecoat1c.search( output_escape )
 bluecoatmethod2a = bluecoatmethod2c.search( output_escape )
 bluecoatmethod3a = bluecoatmethod3c.search( output_escape )
 mcafeewg2 = mcafeewg1.search( output_escape )

 if re.search( r'^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)?(?:\s(\S+)\s\S+\:\s)?(?:\#Software\: |\#Version\: |\#Start-Date\: |\#Date\: |\#Fields\: |\#Remark\: )', output_escape):
  if debug2: print("bypass BlueCoat header.")

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
 elif squiddefault2:
  timestamp_central=squiddefault2.group(1); server_hostname_ip=squiddefault2.group(2); timestamp_unix=squiddefault2.group(3); client_hostname_ip=squiddefault2.group(4); http_reply_code=squiddefault2.group(5); client_http_method=squiddefault2.group(6); client_http_uri=squiddefault2.group(7); web_hostname_ip=squiddefault2.group(8);
  if not squiddefault2.group(1): timestamp_central="N/A"
  if not squiddefault2.group(2): server_hostname_ip="N/A"
  if debug2: print("passage dans squid default regexp.")
  client_username=0


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
 elif squidua2:
  timestamp_central=squidua2.group(1); server_hostname_ip=squidua2.group(2); client_hostname_ip=squidua2.group(3); http_reply_code=squidua2.group(4); timestamp_unix=squidua2.group(5); client_http_method=squidua2.group(6); client_http_uri=squidua2.group(7); web_hostname_ip=squidua2.group(8); client_http_useragent=squidua2.group(9); client_http_referer=squidua2.group(10); client_http_cookie=squidua2.group(11); server_remote_ip=squidua2.group(12);
  if not squidua2.group(1): timestamp_central="N/A"
  if not squidua2.group(2): server_hostname_ip="N/A"
  if debug2: print("passage dans squid added User-Agent regexp.")
  client_username=0


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
 elif apache2:
  timestamp_central=apache2.group(1); server_hostname_ip=apache2.group(2); client_hostname_ip=apache2.group(3); client_username=apache2.group(4); timestamp_unix=apache2.group(5); client_http_method=apache2.group(6); client_http_uri=apache2.group(7); http_reply_code=apache2.group(8); client_http_referer=apache2.group(9); client_http_useragent=apache2.group(10); client_http_cookie=apache2.group(11);
  if debug2: print("passage dans Apache User-Agent regexp.")
  if apache2.group(4) == "-": client_username=0


# log proxy TMG/FOREFRONT:
# 10.0.0.1     DOMAINE\USERNAME     Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)     2013-07-21      00:00:00        SERVERNAME      http://abc.com/abcd       -       10.0.0.2  8080    4493    625     291     http    GET     http://abc.com/def     Upstream 200
#10.0.0.1     anonymous       Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) 2013-07-21      00:00:12        SERVERNAME      http://www.google.com/22  855560    www.google.com  10.0.0.2     8085    1       1112    4587    http    GET     http://www.google.com/ - 12209
#10.0.0.1      anonymous       Microsoft-CryptoAPI/6.1 2013-07-21      04:54:20        SERVERNAME      -       rapidssl-crl.geotrust.com       10.0.0.2     8085    1       180     4587    http        GET     http://rapidssl-crl.geotrust.com/crls/rapidssl.crl      -       12209
#10.0.0.1\tanonymous\tMozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)\t2013-07-21\t00:01:06\tSERVERNAME\t-\t-\t10.0.0.2\t443\t0\t0\t544\tSSL-tunnel\t-\tmail.google.com:443\tInet\t407
#10.0.0.1       DOMAINE\USERNAME        Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) 2013-06-21      00:00:13        SERVERNAME      -       -       10.0.0.2        8085    0       1695    1532    SSL-tunnel      -       www.marketscore.com:443 Upstream        0
#10.0.0.1       DOMAINE\USERNAME        Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) 2013-06-21      00:00:24        SERVERNAME      -       www.marketscore.com     10.0.0.2        443     31      938     448     SSL-tunnel      CONNECT -       -       12210
 elif tmg2:
  client_hostname_ip=tmg2.group(1); client_username=tmg2.group(2); client_http_useragent=tmg2.group(3); timestamp_central=tmg2.group(4)+" "+tmg2.group(5); server_hostname_ip=tmg2.group(6); client_http_referer=tmg2.group(7); client_http_method=tmg2.group(9); client_http_uri=tmg2.group(10); http_reply_code=tmg2.group(11);
  # https/ssl-tunnel:
  if client_http_uri == "-" and tmg2.group(8) != "-":
   client_http_uri=tmg2.group(8)
  if debug2: print("passage dans TMG/ForeFront regexp.")


# log proxy BlueCoat sans http_method:
# <161>Aug 21 21:59:59 srv log: 2014-08-21 22:00:00 2 10.0.0.2 - - "none" PROXIED 407 - TCP_DENIED - http tools.google.com 80 /service/update2 ?w=6 "Google Update" 10.0.0.3 1681 1665 -
 #elsif ( $output_escape =~ /^(?:\<\d+\>)?(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(\S+)\s)?(?:\S+\:\s)?(\d{4}\-\d{2}\-\d{2})\s(\d{2}\:\d{2}\:\d{2})\s\d+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\S+)\s(?:\-|\S+)\s\\\"[^\"]*?\\\"\s\S+\s(\d+)\s(\S+)\s\S+\s\S+\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(?:\\\"([^\"]*?)\\\"|(\-))\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d+\s\d+\s\-\s?\\?r?$/ ) {
 # $server_hostname_ip=$1; $timestamp_central=$2." ".$3; $client_hostname_ip=$4; $client_username=$5; $http_reply_code=$6; $client_http_referer=$7; $client_http_uri="$8:\/\/$9$11$12"; $client_http_useragent=$13;
 # if( $8 eq "tcp" && $12 ne "-" ) { $client_http_uri=$9 }
 # unless( $13 ) { $client_http_useragent=$14 }
 # if( $12 eq "-" && $8 ne "tcp" ) { $client_http_uri="$8:\/\/$9$11" }
 # elsif( $12 eq "-" && $8 eq "tcp" ) { $client_http_uri="$9$11" }
 # print "passage dans BlueCoat sans http_method regexp.\n" if $debug2;
 elif bluecoat1a:
  server_hostname_ip=bluecoat1a.group(1); timestamp_central=bluecoat1a.group(2)+" "+bluecoat1a.group(3); client_hostname_ip=bluecoat1a.group(4); client_username=bluecoat1a.group(5); http_reply_code=bluecoat1a.group(6); client_http_referer=bluecoat1a.group(7); client_http_uri=bluecoat1a.group(8)+":\/\/"+bluecoat1a.group(9)+bluecoat1a.group(11)+bluecoat1a.group(12); client_http_useragent=bluecoat1a.group(13);
  if bluecoat1a.group(8) == "tcp" and bluecoat1a.group(12) != "-":
   client_http_uri=bluecoat1a.group(9)
  if not bluecoat1a.group(13):
   client_http_useragent=bluecoat1a.group(14)
  if bluecoat1a.group(12) == "-" and bluecoat1a.group(8) != "tcp":
   client_http_uri=bluecoat1a.group(8)+":\/\/"+bluecoat1a.group(9)+bluecoat1a.group(11)
  elif bluecoat1a.group(12) == "-" and bluecoat1a.group(8) == "tcp":
   client_http_uri=bluecoat1a.group(9)+bluecoat1a.group(11)
  if debug2: print("passage dans BlueCoat 1 sans http_method regexp.")


# log proxy BlueCoat avec http_method:
# Fields: (syslog header)           date       time  time-taken c-ip cs-username cs-auth-group cs-categories sc-filter-result sc-status cs(Referer) s-action rs(Content-Type) cs-method cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs(User-Agent) s-ip sc-bytes cs-bytes x-virus-id
# Jan 10 11:10:21 10.0.0.1/10.0.0.1 2013-10-10 11:10:21 68 10.0.0.2 - - \"bc_rules\" CATEGORY 304 http://referer.com TCP_HIT image/gif GET http www.test.com 80 /path.gif - \"Mozilla/4.0\" 10.0.0.3 370 665 -
# Oct 10 11:10:21 10.0.0.1/10.0.0.1 2013-10-10 11:10:22 135 10.0.0.2 user group \"none\" CATEGORY 200 http://referer.com TCP_CLIENT_REFRESH application/javascript GET http www.test.com 80 /path.js - \"Mozilla/4.0\" 10.0.0.3 22159 568 -
# Oct 10 11:10:21 10.0.0.1/10.0.0.1 2013-10-10 11:10:23 15 10.0.0.2 user group \"none\" CATEGORY 204 - TCP_NC_MISS text/html GET http www.test.com 80 /path ?arg=1 \"Mozilla/4.0\" 10.0.0.3 321 491 -
# Oct 10 11:10:21 10.0.0.1/10.0.0.1 2013-10-10 11:10:24 1 10.0.0.2 - - \"none\" CATEGORY 407 - TCP_DENIED - CONNECT tcp www.test.com 443 / - \"Mozilla/4.0\" 10.0.0.3 330 308 -
 elif bluecoatmethod2a:
  server_hostname_ip=bluecoatmethod2a.group(1); timestamp_central=bluecoatmethod2a.group(2)+" "+bluecoatmethod2a.group(3); client_hostname_ip=bluecoatmethod2a.group(4); client_username=bluecoatmethod2a.group(5); http_reply_code=bluecoatmethod2a.group(6); client_http_referer=bluecoatmethod2a.group(7); client_http_method=bluecoatmethod2a.group(8); client_http_uri=bluecoatmethod2a.group(9)+":\/\/"+bluecoatmethod2a.group(10)+bluecoatmethod2a.group(12)+bluecoatmethod2a.group(13); client_http_useragent=bluecoatmethod2a.group(14);
  if bluecoatmethod2a.group(9) == "tcp" and bluecoatmethod2a.group(13) != "-":
   client_http_uri=bluecoatmethod2a.group(10)
  if not bluecoatmethod2a.group(13):
   client_http_useragent=bluecoatmethod2a.group(14)
  if bluecoatmethod2a.group(13) == "-" and bluecoatmethod2a.group(9) != "tcp":
   client_http_uri=bluecoatmethod2a.group(9)+":\/\/"+bluecoatmethod2a.group(10)+bluecoatmethod2a.group(12)
  elif bluecoatmethod2a.group(13) == "-" and bluecoatmethod2a.group(9) == "tcp":
   client_http_uri=bluecoatmethod2a.group(10)+bluecoatmethod2a.group(12)
  if debug2: print("passage dans BlueCoat 2 avec http_method regexp.")


# Format MAIN SGOS v6.5.5.5
#Fields: date time time-taken c-ip sc-status s-action sc-bytes cs-bytes cs-method cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs-username cs-auth-group s-supplier-name rs(Content-Type) cs(Referer) cs(User-Agent) sc-filter-result cs-categories x-virus-id s-ip
#2014-12-27 19:32:40 306 10.0.0.1 200 TCP_ACCELERATED 39 213 CONNECT tcp snippets.mozilla.com 443 / - - - 172.16.0.1 - - "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:20.0) Gecko/20130416 Firefox/20.0" OBSERVED "Technology/Internet" - 172.16.0.1
#2014-12-27 19:32:40 70 10.0.0.1 200 TCP_NC_MISS 1665 512 POST http gtssl-ocsp.geotrust.com 80 / - - - gtssl-ocsp.geotrust.com application/ocsp-response - "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:20.0) Gecko/20130416 Firefox/20.0" OBSERVED "Technology/Internet" - 172.16.0.1
#2014-12-27 19:36:58 27 10.0.0.1 200 TCP_NC_MISS 411 731 GET http www.google.fr 80 /6407654/ ?label=All - - www.google.fr image/gif http://www.test.fr/ "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:20.0) Gecko/20130416 Firefox/20.0" OBSERVED "Search Engines/Portals" - 172.16.0.1
#2014-12-27 19:36:59 1 10.0.0.1 0 DENIED 0 0 unknown ssl webanalytics.btelligent.net 443 / - - - webanalytics.btelligent.net - - - DENIED "Placeholders" - 172.16.0.1
 elif bluecoatmethod3a:
  server_hostname_ip=bluecoatmethod3a.group(1); timestamp_central=bluecoatmethod3a.group(2)+" "+bluecoatmethod3a.group(3); client_hostname_ip=bluecoatmethod3a.group(4); http_reply_code=bluecoatmethod3a.group(5); client_http_method=bluecoatmethod3a.group(6); client_http_uri=bluecoatmethod3a.group(7)+":\/\/"+bluecoatmethod3a.group(8)+bluecoatmethod3a.group(10)+bluecoatmethod3a.group(11); client_username=bluecoatmethod3a.group(12); client_http_referer=bluecoatmethod3a.group(13); client_http_useragent=bluecoatmethod3a.group(14); server_remote_ip=bluecoatmethod3a.group(16);
  if bluecoatmethod3a.group(7) == "tcp" and bluecoatmethod3a.group(11) != "-":
   client_http_uri=bluecoatmethod3a.group(8)
  if bluecoatmethod3a.group(11) == "-" and bluecoatmethod3a.group(7) != "tcp":
   client_http_uri=bluecoatmethod3a.group(7)+":\/\/"+bluecoatmethod3a.group(8)+bluecoatmethod3a.group(10)
  elif bluecoatmethod3a.group(11) == "-" and bluecoatmethod3a.group(7) == "tcp":
   client_http_uri=bluecoatmethod3a.group(8)+bluecoatmethod3a.group(10)
  if debug2: print("passage dans BlueCoat 3 avec http_method regexp.")


# log proxy McAfee WebGateway default v7.2.x (missing Referer and Cookie)
# [1/Mar/2014:17:34:07 +0200] \"\" \"\" 10.1.1.1 200 \"POST http://google.com/test?test HTTP/1.1\" \"Category\" \"0 (Minimal Risk)\" \"text/xml\" 818 \"Java/1.6.0_55\" \"McAfeeGW: Optionnal Antivirus\" Cache=\"TCP_MISS_RELOAD\" nexthopname.com
# [1/Mar/2014:17:34:07 +0200] \"dom\\alloa\" \"Policyname\" 10.1.1.1 200 \"GET http://1.1.1.1/abc/def/ghi HTTP/1.1\" \"Content Server, Social Networking\" \"-24 (Unverified)\" \"application/x-fcs\" 270 \"Shockwave Flash\" \"\" Cache=\"TCP_MISS_VERIFY\" nexthopname.com
# [1/Mar/2014:17:34:11 +0200] \"\" \"\" 10.1.1.1 200 \"CONNECT ssl.google-analytics.com:443 HTTP/1.1\" \"Internet Services\" \"3 (Minimal Risk)\" \"\" 6847 \"Mozilla/5.0 (compatible; MSIE 11.0; Windows NT 7.1; Trident/5.0)\" \"\" Cache=\"TCP_MISS\" nexthopname.com
# 2013-11-22T22:01:49.577030+01:00 hostname programname: [1/Mar/2014:17:34:11 +0200] \"\" \"\" 10.1.1.1 200 \"CONNECT ssl.google-analytics.com:443 HTTP/1.1\" \"Internet Services\" \"3 (Minimal Risk)\" \"\" 6847 \"Mozilla/5.0 (compatible; MSIE 11.0; Windows NT 7.1; Trident/5.0)\" \"\" Cache=\"TCP_MISS\" nexthopname.com
 elif mcafeewg2:
  server_hostname_ip=mcafeewg2.group(1); timestamp_central=mcafeewg2.group(2); client_username=mcafeewg2.group(3); client_hostname_ip=mcafeewg2.group(4); http_reply_code=mcafeewg2.group(5); client_http_method=mcafeewg2.group(6); client_http_uri=mcafeewg2.group(7); client_http_useragent=mcafeewg2.group(8);
  if not mcafeewg2.group(8):
   client_http_useragent="-"
  if debug2: print("passage dans McAfee default regexp.")


 else:
  if args.s:
   syslog.sendall( socketgethostname+" etplc: aucun parser ne correspond au motif !!! "+output_escape)
  else:
   print("aucun parser ne correspond au motif !!! "+output_escape)

 if timestamp_central and debug2: sys.stdout.write( "timestamp_central: "+timestamp_central )
 if server_hostname_ip and debug2: sys.stdout.write( ", server_hostname_ip: "+server_hostname_ip )
 if timestamp_unix and debug2: sys.stdout.write( ", timestamp_unix: "+timestamp_unix )
 if client_hostname_ip and debug2: sys.stdout.write( ", client_hostname_ip: "+client_hostname_ip )
 if client_username and debug2: sys.stdout.write( ", client_username: "+client_username )
 if http_reply_code and debug2: sys.stdout.write( ", http_reply_code: "+http_reply_code )
 if client_http_method and debug2: sys.stdout.write( ", client_http_method: "+client_http_method )
 if client_http_uri and debug2: sys.stdout.write( ", client_http_uri: "+client_http_uri )
 if web_hostname_ip and debug2: sys.stdout.write( ", web_hostname_ip: "+web_hostname_ip )
 if client_http_useragent and debug2: sys.stdout.write( ", client_http_useragent: "+client_http_useragent )
 if client_http_referer and debug2: sys.stdout.write( ", client_http_referer: "+client_http_referer )
 if client_http_cookie and debug2: sys.stdout.write( ", client_http_cookie: "+client_http_cookie )
 if server_remote_ip and debug2: sys.stdout.write( ", server_remote_ip: "+server_remote_ip )
 if timestamp_central and debug2: sys.stdout.write( "\n" )

####################################################################################################

 # de-encoded char :
 if client_http_uri:
  countloop=0
  while '%' in client_http_uri:
   countloop += 1
   client_http_uri=urllib.unquote(client_http_uri)
   if debug2: print("unescape: "+client_http_uri)
   if countloop>4: break
  if '\x00' in client_http_uri:
   client_http_uri=re.sub( r'\x00', r'%00', client_http_uri )
   if debug2: print("ok found null byte")
  if '\x0d' in client_http_uri:
   client_http_uri=re.sub( r'\x0d', r'%0D', client_http_uri )
   if debug2: print("ok found cr byte")
  if '\x0a' in client_http_uri:
   client_http_uri=re.sub( r'\x0a', r'%0A', client_http_uri )
   if debug2: print("ok found lf byte")

####################################################################################################

 jump=0 # required here for global variables
 if client_http_uri:
  etmsg=0
  foundmethod=0
  founduricourt=0
  foundurilong=0
  foundurilongdistance=0
  foundagent=0
  foundreferer=0
  foundpcrereferer=0
  foundpcreuri=0
  foundpcreagent=0
  foundcookie=0
  foundpcrecookie=0
  foundremoteip=0
  etmsg_old=0
  paslememe=0

  for etmsg,clef in sorted(set(dict)):
   #jump=0 # required here for global variables
   paslememe=0
   values=dict[etmsg,clef]

   if debug2: print("---------------")
   if debug2: print("hash0 etmsg: "+etmsg+", clef: "+clef+", values: "+str(values))
   if jump and debug2: print("ok jump")

   if etmsg_old == etmsg and jump:
    if debug2: print("ok c'est le meme et jump")
    next
   #if etmsg_old == etmsg:
   # print "ok c'est le meme"
    #next
   if etmsg_old and etmsg_old != etmsg:
    if debug2: print("ok ce n'est pas le meme")
    jump=0 # required here for global variables
    paslememe=1

   if paslememe and not jump and ( foundmethod or founduricourt or foundurilong or foundurilongdistance or foundagent or foundreferer or foundpcrereferer or foundpcreagent or foundcookie or foundpcrecookie or foundpcreuri or foundremoteip ):
    if debug2: print("ok ici10")
    alertetplc = "ok trouvé: "
    if timestamp_central:     alertetplc += "timestamp: "+timestamp_central+", "
    if server_hostname_ip:    alertetplc += "server_hostname_ip: "+server_hostname_ip+", "
    if client_hostname_ip:    alertetplc += "client_hostname_ip: "+client_hostname_ip+", "
    if client_username:       alertetplc += "client_username: "+client_username+", "
    if client_http_method:    alertetplc += "client_http_method: "+client_http_method+", "
    if client_http_uri:       alertetplc += "client_http_uri: "+client_http_uri+", "
    if client_http_useragent: alertetplc += "client_http_useragent: "+client_http_useragent+", "
    if client_http_referer:   alertetplc += "client_http_referer: "+client_http_referer+", "
    if client_http_cookie:    alertetplc += "client_http_cookie: "+client_http_cookie+", "
    if server_remote_ip:      alertetplc += "server_remote_ip: "+server_remote_ip+", "
    if http_reply_code:       alertetplc += "http_reply_code: "+http_reply_code+", "
    if etmsg:                 alertetplc += "etmsg: "+etmsg_old
    if foundmethod:           alertetplc += ", etmethod: "+foundmethod
    if founduricourt:         alertetplc += ", eturishort: "+founduricourt
    if foundurilong:          alertetplc += ", eturilong: "+foundurilong
    if foundurilongdistance:  alertetplc += ", eturilongdistance: "+foundurilongdistance
    if foundagent:            alertetplc += ", etagent: "+foundagent
    if foundreferer:          alertetplc += ", etreferer: "+foundreferer
    if foundpcrereferer:      alertetplc += ", etpcrereferer: "+foundpcrereferer
    if foundpcreagent:        alertetplc += ", etpcreagent: "+foundpcreagent
    if foundcookie:           alertetplc += ", etcookie: "+foundcookie
    if foundpcrecookie:       alertetplc += ", etpcrecookie: "+foundpcrecookie
    if foundpcreuri:          alertetplc += ", etpcreuri: "+foundpcreuri
    if foundremoteip:         alertetplc += ", etremoteip: "+foundremoteip
    alertetplc += "\n"
    if args.s:
     syslog.sendall( socketgethostname+" etplc: "+alertetplc )
    else:
     sys.stdout.write( alertetplc )
     #sys.stdout.write( alertetplc+"\n" )
    paslememe=0
    jump=0
    foundmethod=0
    founduricourt=0
    foundurilong=0
    foundurilongdistance=0
    foundagent=0
    foundreferer=0
    foundpcrereferer=0
    foundpcreagent=0
    foundcookie=0
    foundpcrecookie=0
    foundpcreuri=0
    foundremoteip=0

   etmsg_old=etmsg
   if debug2: print("hash2 etmsg: "+etmsg+", clef: "+clef+", values: "+str(values))

   if clef == "httpmethod" and not jump:
    if debug2: print("ok ici1")
    if client_http_method and (values[1] == "nocase" or values[1] == "fast_pattern") and values[0].lower() in client_http_method.lower():
     if debug2: print("ici1a: "+values[0])
     foundmethod=values[0]
    elif client_http_method and values[0] in client_http_method:
     if debug2: print("ici1b: "+values[0])
     foundmethod=values[0]
    elif values[0]:
     if debug2: print("method not found: jump ("+values[0]+")")
     jump=1
     foundmethod=0
     founduricourt=0
     foundurilong=0
     foundurilongdistance=0
     foundagent=0
     foundreferer=0
     foundpcrereferer=0
     foundpcreagent=0
     foundcookie=0
     foundpcrecookie=0
     foundpcreuri=0
     foundremoteip=0
     next

   elif clef == "httpuricourt" and not jump:
    if debug2: print("ok ici2")
    if client_http_uri and values in client_http_uri.lower():
     if debug2: print("ici2: "+values)
     founduricourt=values
    elif values:
     if debug2: print("urishort not found: jump ("+values+")")
     jump=1
     foundmethod=0
     founduricourt=0
     foundurilong=0
     foundurilongdistance=0
     foundagent=0
     foundreferer=0
     foundpcrereferer=0
     foundpcreagent=0
     foundcookie=0
     foundpcrecookie=0
     foundpcreuri=0
     foundremoteip=0
     next

   elif clef == "httpurilong" and not jump:
    if debug2: print("ok ici3")
    foundurilong=str(values)
    for abc in values:
     if not jump and client_http_uri and abc in client_http_uri.lower():
      if debug2: print("ici3: "+abc)
     elif not jump: # out on first jump
      if debug2: print("uri not found: jump ("+abc+")")
      jump=1
      foundmethod=0
      founduricourt=0
      foundurilong=0
      foundurilongdistance=0
      foundagent=0
      foundreferer=0
      foundpcrereferer=0
      foundpcreagent=0
      foundcookie=0
      foundpcrecookie=0
      foundpcreuri=0
      foundremoteip=0
      next

   elif clef == "httpurilongdistance" and not jump:
    if debug2: print("ok ici9")
    foundurilongdistance=str(values)
    for abc in values:
     if not jump and client_http_uri and abc in client_http_uri.lower():
      if debug2: print("ici9: "+abc)
     elif not jump: # out on first jump
      if debug2: print("uri distance not found: jump ("+abc+")")
      jump=1
      foundmethod=0
      founduricourt=0
      foundurilong=0
      foundurilongdistance=0
      foundagent=0
      foundreferer=0
      foundpcrereferer=0
      foundpcreagent=0
      foundcookie=0
      foundpcrecookie=0
      foundpcreuri=0
      foundremoteip=0
      next

   elif clef == "httpagentshort" and not jump:
    if debug2: print("ok ici4")
    if client_http_useragent and values in client_http_useragent.lower():
     if debug2: print("ici4: "+values)
     foundagent=values
    elif values:
     if debug2: print("agent not found: jump ("+values+")")
     jump=1
     foundmethod=0
     founduricourt=0
     foundurilong=0
     foundurilongdistance=0
     foundagent=0
     foundreferer=0
     foundpcrereferer=0
     foundpcreagent=0
     foundcookie=0
     foundpcrecookie=0
     foundpcreuri=0
     foundremoteip=0
     next

   elif clef == "httpreferer" and not jump:
    if debug2: print("ok ici10")
    if client_http_referer and values in client_http_referer.lower():
     if debug2: print("ici10a: "+values)
     foundreferer=values
    elif values:
     if debug2: print("httpreferer not found: jump ("+values+")")
     jump=1
     foundmethod=0
     founduricourt=0
     foundurilong=0
     foundurilongdistance=0
     foundagent=0
     foundreferer=0
     foundpcrereferer=0
     foundpcreagent=0
     foundcookie=0
     foundpcrecookie=0
     foundpcreuri=0
     foundremoteip=0
     next

   elif clef == "httpcookie" and not jump:
    if debug2: print("ok ici11")
    if client_http_cookie and (values[1] == "nocase" or values[1] == "fast_pattern") and values[0].lower() in client_http_cookie.lower():
     if debug2: print("ici11a: "+values[0])
     foundcookie=values[0]
    elif client_http_cookie and values[0] in client_http_cookie:
     if debug2: print("ici11b: "+values[0])
     foundcookie=values[0]
    elif values[0]:
     if debug2: print("cookie not found: jump ("+values[0]+")")
     jump=1
     foundmethod=0
     founduricourt=0
     foundurilong=0
     foundurilongdistance=0
     foundagent=0
     foundreferer=0
     foundpcrereferer=0
     foundpcreagent=0
     foundcookie=0
     foundpcrecookie=0
     foundpcreuri=0
     foundremoteip=0
     next

   elif clef == "pcrereferer" and not jump:
    if debug2: print("ok ici5")
    if values and '^\-$' == values:
     if debug2: print("ici5b: "+values)
     foundpcrereferer=values
    elif client_http_referer and re.search( r''+values, client_http_referer, re.I ):
     if debug2: print("ici5a: "+values)
     foundpcrereferer=values
    elif values:
     if debug2: print("pcrereferer not found: jump ("+values+")")
     jump=1
     foundmethod=0
     founduricourt=0
     foundurilong=0
     foundurilongdistance=0
     foundagent=0
     foundreferer=0
     foundpcrereferer=0
     foundpcreagent=0
     foundcookie=0
     foundpcrecookie=0
     foundpcreuri=0
     foundremoteip=0
     next

   elif clef == "pcreagent" and not jump:
    if debug2: print("ok ici6")
    if values and '^\-$' == values[0]:
     if debug2: print("ici6c: "+values)
    elif client_http_useragent and (values[1] == "nocase" or values[1] == "fast_pattern") and re.search( r''+values[0], client_http_useragent, re.I ):
     if debug2: print("ici6a: "+values[0])
     foundpcreagent=values[0]
    elif client_http_useragent and (values[1] != "nocase" or values[1] != "fast_pattern") and re.search( r''+values[0], client_http_useragent ):
     if debug2: print("ici6b: "+values[0])
     foundpcreagent=values[0]
    elif values[0]:
     if debug2: print("pcreagent not found: jump ("+values[0]+")")
     jump=1
     foundmethod=0
     founduricourt=0
     foundurilong=0
     foundurilongdistance=0
     foundagent=0
     foundreferer=0
     foundpcrereferer=0
     foundpcreagent=0
     foundcookie=0
     foundpcrecookie=0
     foundpcreuri=0
     foundremoteip=0
     next

   elif clef == "pcrecookie" and not jump:
    if debug2: print("ok ici7")
    if client_http_cookie and values and re.search( r''+values, client_http_cookie, re.I ):
     if debug2: print("ici7: "+values)
     foundpcrecookie=values
    elif values:
     if debug2: print("pcrecookie not found: jump ("+values+")")
     jump=1
     foundmethod=0
     founduricourt=0
     foundurilong=0
     foundurilongdistance=0
     foundagent=0
     foundreferer=0
     foundpcrereferer=0
     foundpcreagent=0
     foundcookie=0
     foundpcrecookie=0
     foundpcreuri=0
     foundremoteip=0
     next

   elif clef == "pcreuri" and not jump:
    if debug2: print("ok ici8")
    if client_http_uri and (values[1] == "nocase" or values[1] == "fast_pattern") and re.search( r''+values[0], client_http_uri, re.I ):
     if debug2: print("ici8a: "+values[0])
     foundpcreuri=values[0]
    elif client_http_uri and (values[1] != "nocase" or values[1] != "fast_pattern") and re.search( r''+values[0], client_http_uri ): 
     if debug2: print("ici8b: "+values[0])
     foundpcreuri=values[0]
    elif values[0]:
     if debug2: print("pcreuri not found: jump ("+values[0]+")")
     jump=1
     foundmethod=0
     founduricourt=0
     foundurilong=0
     foundurilongdistance=0
     foundagent=0
     foundreferer=0
     foundpcrereferer=0
     foundpcreagent=0
     foundcookie=0
     foundpcrecookie=0
     foundpcreuri=0
     foundremoteip=0
     next

   elif clef == "remoteip" and not jump:
    if debug2: print("ok ici12")
    if server_remote_ip and values and values == server_remote_ip:
     if debug2: print("ici12a: "+values)
     foundremoteip=values
    elif values[0]:
     if debug2: print("remoteip not found: jump ("+values+")")
     jump=1
     foundmethod=0
     founduricourt=0
     foundurilong=0
     foundurilongdistance=0
     foundagent=0
     foundreferer=0
     foundpcrereferer=0
     foundpcreagent=0
     foundcookie=0
     foundpcrecookie=0
     foundpcreuri=0
     foundremoteip=0
     next

 return; # function_logsandsearch()

####################################################################################################

#http://stackoverflow.com/questions/20886565/python-using-multiprocessing-process-with-a-maximum-number-of-simultaneous-pro
pool = multiprocessing.Pool() #use all available cores, otherwise specify the number you want as an argument

#for looplogs in sys.stdin.readlines() :
for looplogs in iter(sys.stdin.readline, ""):
 looplogs = looplogs.strip('\n')
 pool.apply_async(function_logsandsearch, args=(looplogs,))
pool.close()
pool.join()
syslog.close()

