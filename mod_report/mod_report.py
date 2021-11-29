#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import os
import re
import sys
import glob
import json
import redis
import jinja2
import logging
import subprocess
import configparser
from common.database import *
from user_agents import parse
from collections import Counter
from ipwhois import IPWhois

def process_profile_traffic(profile_name,PATH,REDIS_CLIENT):
    """ Function to process the traffic for a given profile. """
    VALID_CAPTURE = False
    SLIPS_RESULT = False
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

                # If capture is meaningful, call Slips
                message=f'process_profile:{profile_name}'
                REDIS_CLIENT.publish('mod_slips_check',message)
                logging.info(f'Requested mod_slips to process the capture {capture_file}')
                ## Wait for slips to finish
                slips_subscriber = redis_create_subscriber(REDIS_CLIENT)
                redis_subscribe_to_channel(slips_subscriber,'slips_processing')
                for item in slips_subscriber.listen():
                    logging.info('Listening for Slips responses')
                    if item['type'] == 'message':
                        logging.info(f"Slips processing: {item['data']}")
                        if 'slips_true' in item['data']:
                            #Good. Continue.
                            SLIPS_RESULT = True
                            break
                        else:
                            #Bad. Continue. Do not retry.
                            SLIPS_RESULT = False
                            break
        return VALID_CAPTURE,SLIPS_RESULT
    except Exception as err:
        logging.info(f'Exception in process_profile_traffic: {err}')
        return False

def generate_slips_report(profile_name,PATH,SLIPS_STATUS):
    try:
        # Processing UNKNOWN_PORT Slips alerts
        pass
    except Exception as err:
        logging.info(f'Exception in generate_slips_report: {err}')
        return False

def generate_profile_automatic_report(profile_name,PATH,SLIPS_STATUS):
    """ Process all the outputs and assemble the report. """
    try:
        template=f'report-template.html'
        report_source=f'{profile_name}.md'
        report_build=f'{profile_name}.pdf'
    except Exception as err:
        logging.info(f'Exception in generate_profile_automatic_report: {err}')

def generate_profile_report(profile_name,PATH,SLIPS_STATUS):
    """ Process all the outputs and assemble the report. """
    try:
        report_source=f'{profile_name}.md'
        report_build=f'{profile_name}.pdf'
        os.chdir(f'{PATH}/{profile_name}')

        # Open report file to generate
        report = open(report_source,'w')
        report.write('# Emergency VPN Automated Report\n')
        report.write("This is an automated report of your Emergency VPN session generated with the Civilsphere AI VPN technology (beta). One of our analysts will review your session and send a follow-up report within the next 30 days.\n")
        report.write('\n')
        report.write("If you are in need of immediate assistance, please contact AccessNow Helpline indicating that you already made the assessment with the Emergency VPN: https://www.accessnow.org/help/.\n")
        report.write('\n')

        # One section per pcap
        for capture_file in glob.glob("20*.pcap"):
            capture_name = capture_file.split('.pcap')[0]
            report.write(f'# Capture {capture_name}\n\n')

            # Generate the capture information
            report.write('## Capture Information\n\n')
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
            report.write('## Top Data Transfers (bytes)\n\n')
            report.write("Malicious applications usually steal data (photos, messages, files, voice recordings) from the device. The stolen data is uploaded to malicious servers. Recognizing which services the device is sending data to is important to identify possible malicious activity.\n")
            report.write('\n')
            report.write("If you do not recognize any of the services listed below and you are a person at risk, we recommend factory resetting the device to remove any suspicious activity. Be advised that a  factory reset will not fix a compromised account (email, iCloud, Google, etc.).\n")
            report.write('\n')
            report.write("These are the top 10 data transfers:\n")
            report.write('\n\n')

            report.write("\scriptsize\n")
            report.write("\\begin{tabular}{lcrrrr}\n")
            report.write("\hline\n")
            report.write("A \\textless{}-\\textgreater B & ASN & B -\\textgreater A & A -\\textgreater B & Total Transferred & Total Duration \\\\ \n")
            report.write(" &  & (bytes) & (bytes) & (bytes) & (seconds)\\\\ \n")
            report.write("\hline\n")

            with open(f'{capture_name}.uploads','r') as file_source:
                file_uploads = json.load(file_source)

            for item in file_uploads:
                SRCIP=item['Source-Destination'].split()[0]
                DSTIP=item['Source-Destination'].split()[2]
                try:
                    # This assumes the public IP is on the A position (A<->B)
                    # If ASN name has weird strings, it will break the LaTeX.
                    ASN=IPWhois(SRCIP).lookup_whois()['asn_description'].replace('_','\_').replace('^','\^').replace('&','\&').replace('$','\$').replace('#','\#')[:20]
                except:
                    ASN="Unknown"

                report.write(f"{SRCIP} \\textless-\\textgreater {DSTIP} & {ASN} & {item['Total Download']} & {item['Total Upload']} & {item['Total Transferred']} & {item['Duration']} \\\\ \n")

            report.write("\hline\n")
            report.write("\end{tabular}\n")
            report.write("\\normalsize \n")
            report.write('\n\n')

            # Generate the DNS information
            report.write('## Top Resolved DNS Requests\n\n')
            report.write("DNS is essential to network communications, and malware also relies on DNS to resolve addresses where to connect. DNS could also be used to tunnel data and steal information. Additionally, DNS helps identify the services the device is using. These are the top 30 DNS domains resolved in this session:\n")
            report.write('\n\n')
            with open(f'{capture_name}.dns','r') as file_source:
                file_dns = json.load(file_source)

            dns_queries = []
            for qry in file_dns:
                dns_queries.append(qry['_source']['layers']['dns.qry.name'][0].replace('.','[.]'))

            dns_counter = Counter(dns_queries)
            for qry in sorted(dns_counter.items(), key=lambda x: x[1], reverse=True)[:30]:
                report.write(f'- {qry[1]} {qry[0]}\n')

            # Generate the HTTP Leak Information
            with open(f'{capture_name}.http','r') as file_source:
                file_http = json.load(file_source)

            http_hosts = []
            try:
                for qry in file_http:
                    http_hosts.append(qry['_source']['layers']['http.host'][0])
            except Exception as err:
                logging.info(f'Error parsing http hosts: {err}')
            if len(http_hosts)>0:
                report.write('\n\n')
                report.write("## Information on Insecure HTTP Requests\n\n")
                report.write("The device communicates without encryption (plain HTTP) with several websites. Each connection that is not encrypted (uses HTTP instead of HTTPS), transfers information that potentially anyone with access to the device traffic can see without major effort. Who can access the traffic? This is illustrated by the Electronic Frontier Foundation at https://www.eff.org/pages/tor-and-https. People that share your WiFi, internet service providers, mobile cellular networks, and others. For maximum privacy, it's better if all connections from the phone are encrypted. If you are a person at risk, we recommend uninstalling all applications that are not essential. Use a VPN when using public and not trusted networks.\n")
                report.write('\n')

                report.write('List of websites visited using HTTP:\n')
                report.write('\n')
                http_hosts_counter = Counter(http_hosts)
                for qry in sorted(http_hosts_counter.items(), key=lambda x: x[1], reverse=True):
                    report.write(f'- {qry[1]} {qry[0].replace(".","[.]")}\n')
                report.write('\n')

                http_uagents = []
                try:
                    for qry in file_http:
                        http_uagents.append(qry['_source']['layers']['http.user_agent'][0])
                except Exception as err:
                    logging.info(f'Error processing the user agents: {err}')

                if len(http_uagents)>0:
                    report.write("Every HTTP connection has many pieces of data, among them the User-Agent. User-Agents identify the device and application so the content is properly shown on the mobile phone. We automatically analyze the User-Agents observed in the insecure connections listed above and automatically extract information that can identify the application and device:\n\n")
                    report.write('\n')
                    http_uagents_counter = Counter(http_uagents)
                    for qry in sorted(http_uagents_counter.items(), key=lambda x: x[1], reverse=True):
                        report.write(f'- {qry[0]}\n')
                        report.write(f'\t- Information extracted: {parse(qry[0])}\n')

            # Generate Slips Report
            slips = []
            try:
                with open(f'slips_{capture_file}/alerts.json','r') as slips_alerts:
                    for alert in slips_alerts.readlines():
                        if re.search('UnknownPort', alert, re.I):
                            jsonalert = json.loads(alert)
                            slips.append(f'{jsonalert["timestamp"]}: {jsonalert["description"]}')
            except Exception as err:
                logging.info("Unable to process Slips results")
                pass

            if len(slips)>0:
                report.write('\n\n')
                report.write('## Slips Automatic Alerts\n\n')
                report.write('Slips is a behavioral-based Python intrusion prevention system that uses machine learning to detect malicious behaviors in the network traffic. Slips is designed to focus on targeted attacks and detection of malware command and control channels. Slips is developed by the Stratosphere Research Laboratory and it is free software (https://stratospherelinuxips.readthedocs.io/en/develop/).\n\n')
                report.write('### Connections to Unknown Ports\n\n')
                report.write('An unknown port may indicate the device is connecting to a new type of service, or it may be a sign of malware. If you do not recognize the connections below, seek help.\n\n')
                for alert in slips:
                    report.write(f'- {alert}\n')

        # Generate final report (PDF)
        report.close()
        logging.info("Running pandoc")
        args=["pandoc",report_source,"--pdf-engine=xelatex","-f","gfm","-V","linkcolor:blue","-V","geometry:a4paper","-V","geometry:top=2cm, bottom=1.5cm, left=2cm, right=2cm", "--metadata=author:Civilsphere Project","--metadata=lang:en-US","-f","markdown","-o",report_build]
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
                    status,slips_status = process_profile_traffic(profile_name,PATH,redis_client)
                    logging.info(f'Status of the processing of profile {profile_name}: {status}')
                    if not status:
                        logging.info('All associated captures were empty')
                        message=f'send_empty_capture:{profile_name}'
                        redis_client.publish('mod_comm_send_check',message)
                        del_profile_to_report(profile_name,redis_client)
                        upd_reported_time_to_expired_profile(profile_name,redis_client)
                        continue
                    if status:
                        status = generate_profile_report(profile_name,PATH,slips_status)
                        logging.info(f'Status of report on profile {profile_name}: {status}')
                        if status:
                            logging.info('Processing of associated captures completed')
                            message=f'send_report_profile:{profile_name}'
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
