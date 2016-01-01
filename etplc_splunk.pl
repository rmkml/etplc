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

# changelog:
#  1jan2016: update
# 31dec2015: initial version

# based on the web page:
#  https://wiki.splunk.com/Community:Search_through_REST_perl
#   http://blogs.splunk.com/2011/08/02/splunk-rest-api-is-easy-to-use/
#    by F.K. 
#    Modified by Masa@Splunk
#

use strict;
use warnings;
#
# modules
#use Data::Dumper;
#$Data::Dumper::Indent=1;
use LWP::UserAgent;  # Module for https calls
#
# aptitude install libxml-simple-perl # on Ubuntu 14.04.3 LTS
use XML::Simple;     # convert xml to hash
use URI::Escape;     # sanitize searches to web friendly characters
#
use JSON;
#
use Getopt::Long;    # GetOptions

###########################################################################################

# flush after every write
$| = 1;

# perl timestamp unix:
my $time=time;
my $timebefore=$time-(60*15);

# Search
#  Note: be careful with quota and special characters
my $SEARCH ="search sourcetype=\"bluecoat:proxysg:access:*\" _indextime >= $timebefore _indextime <= $time| fields host date time bytes_in bytes_out src status user http_method dest url http_referrer http_user_agent http_cookie http_content_type | fields - _raw _time";

# If we want to call a saved search
# $SEARCH = '|savedsearch "DasDnsDQ"';

my $XML = new XML::Simple;
#my $ua = LWP::UserAgent -> new;
my $ua = LWP::UserAgent -> new( ssl_opts => { SSL_verify_mode => 'SSL_VERIFY_NONE'},);

my $post;         # Return object for web call
my $results;      # raw results from Splunk
my $xml;          # pointer to xml hash

my $debug=0;
my $file;
my $base_url;
my $username;
my $password;
my $app;

GetOptions ("base_url=s"=> \$base_url,	# string
            "username=s"=> \$username,	# string
            "password=s"=> \$password,	# string
            "app=s"     => \$app,	# string
            "d"         => \$debug)	# flag
or die("Error in command line arguments\n");

unless( $username=~/^[\w\-\.]+$/ and $password=~/^[\x20-\x7f]+$/ and $app=~/^[\w\-\.]+$/ and $base_url=~/^https?:\/\/[\w\-\.]+(?:\:\d+)?\/?$/ )
{
 print "# ==================================================\n";
 print "# ETPLC Splunk \"Connector\"\n";
 print "# http://etplc.org - Twitter: \@Rmkml\n";
 print "# \n";
 print "# Example: perl etplc_splunk.pl -base_url=https://127.0.0.1:8089 -username=admin -password=changeme -app=search | perl etplc_5nov2015a.pl -f emergingall_sigs30dec2015a_snort290b.rules.gz\n";
 print "# For enable optional debugging, add -d on command line\n";
 print "#==================================================\n";
 exit;
}

###########################################################################################

# Request a session Key 
$post = $ua->post( "$base_url/servicesNS/admin/$app/auth/login", Content => "username=$username&password=$password" );
$results = $post->content;
$xml = $XML->XMLin($results);

# Extract a session key
my $ssid = "Splunk ".$xml->{sessionKey};
print "Session_Key(Authorization): $ssid\n" if $debug;

# Add session key to header for all future calls
$ua->default_header( 'Authorization' => $ssid);

# principal loop begin:
while( 1 )
{
 # Perform a search
 $post = $ua->post( "$base_url/servicesNS/$username/$app/search/jobs", Content => "search=".uri_escape($SEARCH) );
 $results = $post->content;
 $xml = $XML->XMLin($results);

 # Check for valid search
 unless (defined($xml->{sid})) {
   print "Unable to run command\n$results\n" if $debug;
   exit;
}

 # Get Search ID
 my $sid = $xml->{sid};
 print  "SID(Search ID)            : $sid\n" if $debug;

 # Check the search Status
 # Repeat until isDone is 1
 #   <s:key name="isDone">1</s:key>
 my $done;
 do {
   sleep(2);
   $post = $ua->get( "$base_url/services/search/jobs/$sid/");
   $results = $post->content;
   if ( $results =~ /name="isDone">([^<]*)</ ) {
      $done = $1;
   } else {
      $done = '-';
   }
   print "Progress Status:$done: Running\n" if $debug;
 } until ($done eq "1");

 $post = $ua->get( "$base_url/services/search/jobs/$sid/results?output_mode=json&count=0");
 foreach my $f ( @{ decode_json( $post->content )->{'results'} } )
 {
 # etplc squid compatible format:
 #/^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)?(?:\s(\S+)\s\S+\:\s+)?\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+[A-Z\_]+\/(\d+)\s+\-\s+\[(.*?)\]\s+\d+\s+(\S+)\s(?:[^\:]*?\:\/\/)?([^\/]*?)(\/\S*)?\s\-\s[^\/]+\/([^\s]+)\s[^\s]+\s\\\"([^\"]+)\\\" \\\"([^\"]+)\\\" \\\"([^\"]+)\\\"(?:\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?/

  my @month=("Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nob","Dec");
  $timebefore=$f->{"_indextime"} if $f->{"_indextime"};
  my ($timeyear, $timemonth, $timeday);
  if( my $date = $f->{"date"} ){ $date =~ /^(\d\d\d\d)-(\d\d)-(\d\d)$/; $timeyear = $1; $timemonth = $2; $timeday = $3; print $month[--$timemonth]." ".$timeday." " };
  print $f->{"time"}." " if $f->{"time"};
  print $f->{"host"}." squid: " if $f->{"host"};
  print $f->{"bytes_in"}." " if $f->{"bytes_in"};
  print $f->{"src"}." " if $f->{"src"};
  print "TCP_MISS/".$f->{"status"}." " if $f->{"status"};
  if( $f->{"user"} ){ print $f->{"user"}." " } else { print " -" };
  if( $timeyear and $timemonth and $timeday ){ print "[".$timeyear."/".$month[$timemonth]."/".$timeday };
  if( my $timehour = $f->{"time"} ){ $timehour =~ s/-/\//g; print ":".$timehour." +0200] " };
  print $f->{"bytes_out"}." " if $f->{"bytes_out"};
  print $f->{"http_method"}." " if $f->{"http_method"};
  print $f->{"url"}." - " if $f->{"url"};
  if( $f->{"dest"} ){ print "DIRECT/".$f->{"dest"}." " } else { print "- " };
  if( $f->{"http_content_type"} ){ print $f->{"http_content_type"}." " } else { print "- " };
  if( $f->{"http_user_agent"} ){ print "\"".$f->{"http_user_agent"}."\" " } else { print "- " };
  if( $f->{"http_referrer"} ){ print "\"".$f->{"http_referrer"}."\" " } else { print "\"-\" " };
  if( $f->{"http_cookie"} ){ print "\"".$f->{"http_cookie"}."\" " } else { print "\"-\" " };
  if( $f->{"dest"} =~ /^\d+\.\d+\.\d+\.\d+$/ ){ print $f->{"dest"} };
  print "\n";
 }
 $SEARCH ="search sourcetype=\"bluecoat:proxysg:access:*\" _indextime > $timebefore | fields host date time bytes_in bytes_out src status user http_method dest url http_referrer http_user_agent http_cookie http_content_type | fields - _raw _time";
 sleep 2;

} # end principal loop

