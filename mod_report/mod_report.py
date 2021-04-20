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
from collections import Counter

def read_configuration():
    #Read configuration
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_REPORT_CHECK']
    LOG_FILE = config['LOGS']['LOG_REPORT']
    PATH = config['STORAGE']['PATH']

    return REDIS_SERVER,CHANNEL,LOG_FILE,PATH

def process_profile_traffic(profile_name,PATH):
    """ Function to process the traffic for a given profile. """
    VALID_CAPTURE = False
    try:
        # Find all pcaps for the profile and process them
        os.chdir(f'{PATH}/{profile_name}')
        report_source=f'{profile_name}.md'
        report_build=f'{profile_name}.pdf'
        for capture_file in glob.glob("*.pcap"):
            capture_size = os.stat(capture_file).st_size
            logging.info(f'Processing capture {capture_file} ({capture_size} b)')
            # If capture is empty, move to next pcap
            if capture_size < 25:
                continue
            # Capture not empty, process it
            VALID_CAPTURE=True
            logging.info("Running the Pcap Summarizer")
            with open(report_source,"wb") as output:
                process = subprocess.Popen(["/code/pcapsummarizer.sh",capture_file])
                process.wait()
        return VALID_CAPTURE
    except Exception as err:
        logging.info(f'Exception in process_profile_traffic: {err}')
        sys.exit(-1)

def generate_profile_report(profile_name,PATH):
    """ Process all the outputs and assemble the report. """
    try:
        report_source=f'{profile_name}.md'
        report_build=f'{profile_name}.pdf'
        os.chdir(f'{PATH}/{profile_name}')

        # Open report file to generate
        report = open(report_source,'w')
        report.write('# Emergency VPN Report\n')

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
            report.write('### Top Uploads (bytes)\n\n')
            report.write('| Source-Destination | Total Download | Total Upload | Total Transferred | Total Duration |\n')
            report.write('| ----|----:|----:| ----:| ----:|\n')
            with open(f'{capture_name}.uploads','r') as file_source:
                file_uploads = json.load(file_source)

            for item in file_uploads:
                report.write(f"|{item['Source-Destination']}|{item['Total Download']}|{item['Total Upload']}|{item['Total Transferred']}|{item['Duration']}|\n")

            # Generate the DNS information
            report.write('### Top 30 DNS Requests\n\n')
            with open(f'{capture_name}.dns','r') as file_source:
                file_dns = json.load(file_source)

            dns_queries = []
            for qry in file_dns:
                dns_queries.append(qry['_source']['layers']['dns.qry.name'][0])

            dns_counter = Counter(dns_queries)
            for qry in sorted(dns_counter.items(), key=lambda x: x[1], reverse=True)[:30]:
                report.write(f'- {qry[1]} {qry[0]}\n')

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
    # Read configuration file
    REDIS_SERVER,CHANNEL,LOG_FILE,PATH = read_configuration()

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
                    status = generate_profile_report(profile_name,PATH)
                    logging.info(f'Status of report on profile {profile_name}: {status}')
                    if not status:
                        logging.info('All associated captures were empty')
                        message=f'send_empty_capture_email:{profile_name}'
                        redis_client.publish('mod_comm_send_check',message)
                        del_profile_to_report(profile_name,redis_client)
                        upd_reported_time_to_expired_profile(profile_name,redis_client)
                        continue
                    if status:
                        logging.info('Processing of associated captures completed')
                        message=f'send_report_profile_email:{profile_name}'
                        redis_client.publish('mod_comm_send_check',message)
                        status=del_profile_to_report(profile_name,redis_client)
                        logging.info(f'del_profile_to_report: {status}')
                        status=upd_reported_time_to_expired_profile(profile_name,redis_client)
                        logging.info(f'upd_reported_time_to_expired_profile: {status}')
                        continue
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
