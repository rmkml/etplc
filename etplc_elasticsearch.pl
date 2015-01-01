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

use strict;
use warnings;
use ElasticSearch;

(my $sec,my $min,my $hour,my $mday,my $month,my $year,my $wday,my $yday,my $isdst) = localtime(time);
$year += 1900;
$month += 1; # start zero

# flush after every write
$| = 1;

my $timestampelasticsearch="now-30m";

while (1)
{

 my $es = ElasticSearch->new(
        servers      => '127.0.0.1:9200',
        transport    => 'http',                  # default 'http'
        max_requests => 10_000,                 # default 10_000
#        trace_calls  => 'log_file',
        no_refresh   => 0 | 1,
 );

 # native elasticsearch query language
 my $results;
 $results = $es->search(
       size => 99999,
       index => "logstash-$year.$month.$mday",
       #index => "logstash-2014.10.28",
       sort => [ { '@timestamp' => "asc" }, ],

        query => {
            #filtered => { query => { match_all => {}},
            filtered => { query => { match => { tag => "squid_access" }},
                          #filter => { bool => { must => [ { range => { '@timestamp' => { "gt" => "now-10m" }} } ]
                          filter => { bool => { must => [ { range => { '@timestamp' => { "gt" => $timestampelasticsearch }} } ]
                                              }
                                    }
                        }
        },
 );

 # squid modified format:
 #2014-10-28T17:23:16.646082+01:00 localhost squid_access:   126 127.0.0.1 TCP_REFRESH_UNMODIFIED/200 - [28/Oct/2014:17:23:14 +0100] 2788 GET http://www.gravatar.com/avatar/27b7980e18cec76c38d1730544fa3373? - HIER_DIRECT/www.gravatar.com image/jpeg "Mozilla/5.0 (X11; Linux i686; rv:33.0) Gecko/20100101 Firefox/33.0" "http://search.cpan.org/~drtech/ElasticSearch/lib/ElasticSearch.pm" "-"

 print $timestampelasticsearch=$_->{_source}{'@timestamp'}," ",$_->{_source}{host}," ",$_->{_source}{tag}," 0 ",$_->{_source}{ip_client}," ",$_->{_source}{http_reply}," - ",$_->{_source}{squid_time}," 0 ",$_->{_source}{http_method}," ",$_->{_source}{http_uri}," - ",$_->{_source}{http_domaine}," - \"",$_->{_source}{http_useragent},"\" \"",$_->{_source}{http_referer},"\" \"",$_->{_source}{http_cookie},"\"\n" for @{ $results->{hits}{hits} };

 sleep 1;
}

