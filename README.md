# Welcome E.T. Proxy Logs Checker [ETPLC].

Started a new Open Source project for Checking Proxy Logs with Emerging Threats Open rules.

It's a production ready version, all feedback is welcome.

Follow project on http://etplc.org or http://sourceforge.net/projects/etplc/ or https://github.com/rmkml/etplc.

Native Perl version and new version based on Python (v3 and v2) script.

New Alpha purpose Elasticsearch "Connector" with ETPLC project here.

# How it's work:

Before, check if you use last Emerging Threats Open rules on download page.

## perl

* realtime: `tail -f /var/log/messages | perl etplc.pl -f emergingall_sigs_snort290b.rules`
* realtime through syslog:  `tail -f /var/log/messages | perl etplc.pl -s -f emergingall_sigs_snort290b.rules`
* offline: `cat /var/log/messages | perl etplc.pl -f emergingall_sigs_snort290b.rules`

## python

* realtime: `tail -f /var/log/messages | python2 etplc.py -f emergingall_sigs_snort290b.rules`
* realtime through syslog: `tail -f /var/log/messages | python2 etplc.py -s -f emergingall_sigs_snort290b.rules`
* offline: `cat /var/log/messages | python2 etplc.py -f emergingall_sigs_snort290b.rules`

###new option Category restrict Logs Checking,
if your Logs contains ProxyLogs use -c proxy, if your Logs contains WebServer use -c webserver, by default or without this option use any logs checking.

if you need debug, enable on command line: -d

if you run etplc script and you have this error: `aucun parser ne correspond au motif !!! ...`
-> sorry etplc unrecognized your logs, please submit to the list.

Don't forget, for best recognize vulnerabilities, you need enable extra logs options like Referer/User-Agent/Cookie.

Etplc project recognize SSL Connect on your logs, if not please submit to the list.

Thx you Emerging Threats Open Community.

ETPLC script design on 3 parts:

* first load and convert Emerging Threats Open rules
* second parse Proxy Logs
* third matching ET_rules <=> Proxy_logs


You can follow ETPLC project on etplc-users@lists.sourceforge.net

Contact: rmkml@yahoo.fr / Twitter: [@Rmkml](https://twitter.com/rmkml)

Etplc project src code are under the GPLv2.
A copy of that license is available at http://www.gnu.org/licenses/gpl-2.0.html

Follow [@Rmkml](https://twitter.com/rmkml)