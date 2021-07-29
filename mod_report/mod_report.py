#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import os
import sys
import glob
import json
import redis
import logging
import subprocess
import configparser
from common.database import *
from user_agents import parse
from collections import Counter

def process_profile_traffic(profile_name,PATH):
    """ Function to process the traffic for a given profile. """
    VALID_CAPTURE = False
    try:
        # Find all pcaps for the profile and process them
        os.chdir(f'{PATH}/{profile_name}')

        for capture_file in glob.glob("*.pcap"):
            capture_size = os.stat(capture_file).st_size
            logging.info(f'Processing capture {capture_file} ({capture_size} b)')

            # If capture is not empty: process it
            if capture_size > 25:
                VALID_CAPTURE=True
                process = subprocess.Popen(["/code/pcapsummarizer.sh",capture_file])
                process.wait()

        return VALID_CAPTURE
    except Exception as err:
        logging.info(f'Exception in process_profile_traffic: {err}')
        return False

def generate_profile_report(profile_name,PATH):
    """ Process all the outputs and assemble the report. """
    try:
        report_source=f'{profile_name}.md'
        report_build=f'{profile_name}.pdf'
        os.chdir(f'{PATH}/{profile_name}')

        # Open report file to generate
        report = open(report_source,'w')
        report.write('# Emergency VPN Automated Report\n')
        report.write('This is an automated report of your Emergency VPN session generated with the Civilsphere AI VPN technology (beta). One of our analysts will review your session and send a follow-up report within the next 30 days.\n')

        # One section per pcap
        for capture_file in glob.glob("*.pcap"):
            capture_name = capture_file.split('.pcap')[0]
            report.write(f'## Capture {capture_name} \n')

            # Generate the capture information
            report.write('### Capture Information\n\n')
            with open(f'{capture_name}.capinfos','r') as file_source:
                file_capinfos = json.load(file_source)
            report.write('\n```\n')
            report.write(f"File name: {file_capinfos[0]['File name']}\n")
            report.write(f"Number of packets: {file_capinfos[0]['Number of packets']}\n")
            report.write(f"File size (bytes): {file_capinfos[0]['File size (bytes)']}\n")
            report.write(f"Start time: {file_capinfos[0]['Start time']}\n")
            report.write(f"End time: {file_capinfos[0]['End time']}\n")
            report.write(f"SHA256: {file_capinfos[0]['SHA256']}\n")
            report.write('```\n')
            report.write('\n')

            # Generate Top Data Transfer
            report.write('### Top Data Transfers (bytes)\n\n')
            report.write("Malicious applications usually steal data (photos, messages, files, voice recordings) from the device. The stolen data is uploaded to malicious servers. Recognizing which services the device is sending data to is important to identify possible malicious activity. If you do not recognize any of the services listed below, we recommend factory resetting the device to remove any suspicious activity. These are the top 5 data transfers:\n")

            report.write('| Source-Destination | Total Download | Total Upload | Total Transferred | Total Duration |\n')
            report.write('| ----|----:|----:| ----:| ----:|\n')

            with open(f'{capture_name}.uploads','r') as file_source:
                file_uploads = json.load(file_source)

            for item in file_uploads:
                report.write(f"|{item['Source-Destination']}|{item['Total Download']}|{item['Total Upload']}|{item['Total Transferred']}|{item['Duration']}|\n")

            # Generate the DNS information
            report.write('### Top Resolved DNS Requests\n\n')
            report.write("DNS is essential to network communications, and malware also relies on DNS to resolve addresses where to connect. DNS could also be used to tunnel data and steal information. Additionally, DNS helps identify the services the device is using. These are the top 30 DNS domains resolved in this session:\n")
            with open(f'{capture_name}.dns','r') as file_source:
                file_dns = json.load(file_source)

            dns_queries = []
            for qry in file_dns:
                dns_queries.append(qry['_source']['layers']['dns.qry.name'][0])

            dns_counter = Counter(dns_queries)
            for qry in sorted(dns_counter.items(), key=lambda x: x[1], reverse=True)[:30]:
                report.write(f'- {qry[1]} {qry[0]}\n')

            # Generate the HTTP Leak Information
            with open(f'{capture_name}.http','r') as file_source:
                file_http = json.load(file_source)

            http_hosts = []
            for qry in file_http:
                http_hosts.append(qry['_source']['layers']['http.host'][0])
            if len(http_hosts)>0:
                report.write("### Information Leaked Via Insecure HTTP Requests\n\n")
                report.write("The device communicates without encryption (plain HTTP) with several websites. Each connection that is not encrypted (uses HTTP instead of HTTPS), transfers information that potentially anyone with access to the device traffic can see without major effort. Who can access the traffic? This is illustrated by the Electronic Frontier Foundation at https://www.eff.org/pages/tor-and-https. People that share your WiFi, internet service providers, mobile cellular networks, and others. For maximum privacy, it's better if all connections from the phone are encrypted. If you are a person at risk, we recommend uninstalling all applications that are not essential. Use a VPN when using public and not trusted networks.\n")

                report.write('List of websites visited using HTTP:\n')
                http_hosts_counter = Counter(http_hosts)
                for qry in sorted(http_hosts_counter.items(), key=lambda x: x[1], reverse=True):
                    report.write(f'- {qry[1]} {qry[0]}\n')
                report.write('\n')

                http_uagents = []
                for qry in file_http:
                    try:
                        http_uagents.append(qry['_source']['layers']['http.user_agent'][0])
                    except:
                        # There may be queries that do not have user-agent.
                        # Ignore
                        pass
                if len(http_uagents)>0:
                    report.write("Every HTTP connection has many pieces of data, among them the User-Agent. User-Agents identify the device and application so the content is properly shown on the mobile phone. We automatically analyze the User-Agents observed in the insecure connections listed above and automatically extract information that can identify the application and device:")
                    http_uagents_counter = Counter(http_uagents)
                    for qry in sorted(http_uagents_counter.items(), key=lambda x: x[1], reverse=True):
                        report.write(f'- ({qry[1]} occurrences) {qry[0]}\n')
                        report.write(f'\t- Information extracted: {parse(qry[0])}\n')

        # Generate final report (PDF)
        report.close()
        logging.info("Running pandoc")
        args=["pandoc",report_source,"--pdf-engine=xelatex","-f","gfm","-V","linkcolor:blue","-V","geometry:a4paper","-V","geometry:top=2cm, bottom=1.5cm, left=2cm, right=2cm", "--metadata=author:Civilsphere Project","--metadata=lang:en-US","-o",report_build]
        process = subprocess.Popen(args)
        process.wait()
        return True
    except Exception as err:
        logging.info(f'Exception in generate_profile_report: {err}')
        return False

if __name__ == '__main__':
    #Read configuration
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_REPORT_CHECK']
    LOG_FILE = config['LOGS']['LOG_REPORT']
    PATH = config['STORAGE']['PATH']

    logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.DEBUG,format='%(asctime)s, MOD_REPORT, %(message)s')

    # Connecting to the Redis database
    try:
        redis_client = redis_connect_to_db(REDIS_SERVER)
    except Exception as err:
        logging.error(f'Unable to connect to the Redis database ({REDIS_SERVER}): {err}')
        sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(redis_client)
    except Exception as err:
        logging.error(f'Unable to create a Redis subscriber: {err}')
        sys.exit(-1)

    # Subscribing to Redis channel
    try:
        redis_subscribe_to_channel(db_subscriber,CHANNEL)
    except Exception as err:
        logging.error(f'Channel subscription failed: {err}')
        sys.exit(-1)

    try:
        logging.info("Connection and channel subscription to redis successful.")

        # Checking for messages
        for item in db_subscriber.listen():
            if item['type'] == 'message':
                logging.info("New message received in channel {}: {}".format(item['channel'],item['data']))
                if item['data'] == 'report_status':
                    redis_client.publish('services_status', 'MOD_REPORT:online')
                    logging.info('MOD_REPORT:online')
                elif 'report_profile' in item['data']:
                    profile_name = item['data'].split(':')[1]
                    logging.info(f'Starting report on profile {profile_name}')
                    status = process_profile_traffic(profile_name,PATH)
                    logging.info(f'Status of the processing of profile {profile_name}: {status}')
                    if not status:
                        logging.info('All associated captures were empty')
                        message=f'send_empty_capture_email:{profile_name}'
                        redis_client.publish('mod_comm_send_check',message)
                        del_profile_to_report(profile_name,redis_client)
                        upd_reported_time_to_expired_profile(profile_name,redis_client)
                        continue
                    if status:
                        status = generate_profile_report(profile_name,PATH)
                        logging.info(f'Status of report on profile {profile_name}: {status}')
                        if status:
                            logging.info('Processing of associated captures completed')
                            message=f'send_report_profile_email:{profile_name}'
                            redis_client.publish('mod_comm_send_check',message)
                            status=del_profile_to_report(profile_name,redis_client)
                            logging.info(f'del_profile_to_report: {status}')
                            status=upd_reported_time_to_expired_profile(profile_name,redis_client)
                            logging.info(f'upd_reported_time_to_expired_profile: {status}')
                            continue
                        else:
                            logging.info(f'Error encountered when generating the report for profile {profile_name}')

        redis_client.publish('services_status', 'MOD_REPORT:offline')
        logging.info("Terminating")
        db_subscriber.close()
        redis_client.close()
        sys.exit(0)
    except Exception as err:
        logging.info(f'Terminating via exception in __main__: {err}')
        db_subscriber.close()
        redis_client.close()
        sys.exit(-1)
