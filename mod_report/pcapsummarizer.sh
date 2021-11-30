#!/bin/bash
# This is an adaptation of the SimplePcapSummarizer

set -o nounset
set -o pipefail

VERSION=0.2
PCAP=$1
FILENAME="${PCAP%.*}"
DIRNAME=$(dirname $FILENAME)
BASENAME=$(basename $FILENAME)
IFS=$'\n'

# Verifying that parameters were given
if [ -z "$1" ];
then
    exit
fi

# This tool will generate the output in JSON format. The files will later be
# processed and assembled together by the report module in order to generate
# the markdown and the PDF.

# Capture information in JSON format
capinfos -TmQ $PCAP | python -c 'import csv, json, sys; print(json.dumps([dict(r) for r in csv.DictReader(sys.stdin)][0]))' > $FILENAME".capinfos"

# HTTP Request information in JSON format
tshark -r $PCAP -Y http.request -T json -e http.host -e http.request.method -e http.request.uri -e http.user_agent -e http.request.version 2>/dev/null > $FILENAME".http"

# DNS Requests information in JSON format
tshark -r $PCAP -T json -Y dns -e dns.qry.name 2>/dev/null | tr '\n' ' ' |tr -s ' ' > $FILENAME".dns"

# Top 10 Uploads JSON format
tshark -qzconv,ipv4 -r $PCAP 2>/dev/null |grep -v "|\|IPv4\|Filter\|=" |sort -n -k 7 -r | head -n 10 | awk 'BEGIN{print "Source-Destination,Total Download,Total Upload,Total Transferred,Duration"}; {print $1" "$2" "$3","$5","$7","$9","$11}; END{}' | python -c 'import csv, json, sys; print(json.dumps([dict(r) for r in csv.DictReader(sys.stdin)]))' > $FILENAME".uploads"

# Get Slips ZEEK stats
ZEEK=$(echo "$DIRNAME/slips_$BASENAME.pcap/zeek_files")
CONN=0 ; DNS=0; HTTP=0; SSL=0
if [ -d "$ZEEK" ];
then
        CONN=$(cat $ZEEK/conn.log | grep -v "#" | wc -l)

        if [ -f "$ZEEK/http.log" ]; then
                HTTP=$(cat $ZEEK/http.log | grep -v "#" | wc -l)
        fi

        if [ -f "$ZEEK/dns.log" ]; then
                DNS=$(cat $ZEEK/dns.log | grep -v "#" | wc -l)
        fi

        if [ -f "$ZEEK/ssl.log" ]; then
                SSL=$(cat $ZEEK/ssl.log | grep -v "#" | wc -l)
        fi

        zeek_json=$(echo '{ "connections": '$CONN', "dns": '$DNS', "http": '$HTTP', "ssl": '$SSL' }')
fi

# Create unique JSON
echo "{ \"capinfos\": $(cat $FILENAME.capinfos),\"top_dns\":$(cat $FILENAME.dns),\"top_uploads\":$(cat $FILENAME.uploads),\"insecure_http\":$(cat $FILENAME.http), \"zeek\": $zeek_json}" > $FILENAME".json"
