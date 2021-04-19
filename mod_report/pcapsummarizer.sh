#!/bin/bash
# This is an adaptation of the SimplePcapSummarizer

set -o nounset
set -o pipefail

VERSION=0.2
PCAP=$1
FILENAME="${PCAP%.*}"
IFS=$'\n'

# Verifying that parameters were given
if [ -z "$1" ];
then
    exit
fi

echo "# Civilsphere AI VPN Report"
echo

echo "## PCAP General Summary"
echo
echo "\`\`\`"
capinfos $PCAP 2>/dev/null  |grep "name:\|packets:\|size:\|duration:\|packet time\|SHA256"
echo "\`\`\`"
echo

echo "## Top Uploads"
echo
echo "| Origin | <-> | Destination | Download | Upload | Total Transferred |"
echo "| -------|:---:|-------- | -------:| -------:| -------: |"
tshark -qzconv,ipv4 -r $PCAP  2>/dev/null |head -n 10 |grep -v "|\|IPv4\|Filter\|===" |awk '{print "| "$1" | <-> | "$3" | "$5" | "$7" | "$9" |"}'
echo

echo "## DNS Requests (Top 30)"
echo
tcpdump -nn -s0 -r $PCAP dst port 53 2>/dev/null |awk -F? '{print $2}' |awk -F "(" '{print $1}' | sort| uniq -c | sort -n -k 1 -r  |head -n 30 | sed 's/^/    /'
echo

echo "## Detailed Findings"
echo "### Information Leaked Via Insecure HTTP Requests"
echo "The mobile device is communicating without encryption (plain HTTP) with several websites. These insecure connections leak information about the user increasing the security risk of the user. We recommend uninstalling all applications that are not strictly necessary. Use a VPN when using public and not trusted networks."
echo 
echo "The list of websites visited using HTTP are listed below: "
echo
tcpdump -nn -s0 -r $PCAP dst port 80 -A 2>/dev/null | grep "Host: " | awk '{print $2}'| awk -F\. '{print $(NF-1)"."$(NF)}' |sort|uniq | sed 's/^/    /'
echo

echo "Additionally, the following information was leaked:"
echo
tcpdump -nn -s0 -r $PCAP -A port 80 and 'tcp[13] & 8 != 0' 2>/dev/null |grep "HTTP:\ GET\ /\|HTTP:\ POST\ /"|grep "?\|=" | awk -F "T " '{print $2}'|sort |uniq |sed 's/^/    /'
echo

echo
tcpdump -nn -s0 -r $PCAP port 80 -A 2>/dev/null |grep "\":{\""| grep -i "wifi\|chrome\|access\|en\|cz\|es\|lang\|com\|loc\|lat\|lon\|imei\|mn\|android\|ios\|build\|time\|format\|[0-9][0-9]\."|sort|uniq -c |sort -n -k 1 -r | sed 's/^/     /'

# This tool will generate the output in JSON format. The files will later be
# processed and assembled together by the report module in order to generate
# the markdown and the PDF.

# Capture information in JSON format
capinfos -TmQ $PCAP | python -c 'import csv, json, sys; print(json.dumps([dict(r) for r in csv.DictReader(sys.stdin)]))' > $FILENAME".capinfos"

# HTTP Request information in JSON format
tshark -r $PCAP -Y http.request -T json -e http.host -e http.request.method -e http.request.uri -e http.user_agent -e http.request.version 2>/dev/null > $FILENAME".http"

# DNS Requests information in JSON format
tshark -r $PCAP -T json -Y dns -e dns.qry.name 2>/dev/null > $FILENAME".dns"
