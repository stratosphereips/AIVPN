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

def process_profile_traffic(profile_name,PATH):
    """ Function to process the traffic for a given profile. """
    VALID_CAPTURE = False
    try:
        # Find all pcaps for the profile and process them
        os.chdir(f'{PATH}/{profile_name}')

        for capture_file in glob.glob("*.pcap"):
            os.mkdir('{PATH}/{profile_name}/slips_{capture_file}')
            capture_size = os.stat(capture_file).st_size
            logging.info(f'Processing capture {capture_file} ({capture_size} b)')

            # If capture is not empty: process it
            if capture_size > 25:
                VALID_CAPTURE=True
                # Run Slips here
                args=['/StratosphereLinuxIPS/slips.py','-c','slips.conf','-f',capture_file,'-o','{PATH}/{profile_name}/slips_{capture_file}']
                process = subprocess.Popen(args,cwd="/StratosphereLinuxIPS", stdout=subprocess.PIPE)
                process.wait()
                return VALID_CAPTURE
        return False
    except Exception as err:
        logging.info(f'Exception in process_profile_traffic: {err}')
        return False

if __name__ == '__main__':
    #Read configuration
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_SLIPS_CHECK']
    LOG_FILE = config['LOGS']['LOG_SLIPS']
    PATH = config['STORAGE']['PATH']

    logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG,format='%(asctime)s, MOD_SLIPS, %(message)s')

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
                    redis_client.publish('services_status', 'MOD_SLIPS:online')
                    logging.info('MOD_SLIPS:online')
                elif 'process_profile' in item['data']:
                    profile_name = item['data'].split(':')[1]
                    logging.info(f'Processing profile {profile_name} with Slips')
                    status = process_profile_traffic(profile_name,PATH)
                    logging.info(f'Status of the processing of profile {profile_name}: {status}')
                    if not status:
                        logging.info('An error occurred processing the capture with Slips')
                        message=f'slips_false:{profile_name}'
                        redis_client.publish('mod_report_check',message)
                        continue
                    if status:
                        logging.info('Processing of associated captures completed')
                        message=f'slips_true:{profile_name}'
                        redis_client.publish('mod_report_check',message)

        redis_client.publish('services_status', 'MOD_SLIPS:offline')
        logging.info("Terminating")
        db_subscriber.close()
        redis_client.close()
        sys.exit(0)
    except Exception as err:
        logging.info(f'Terminating via exception in __main__: {err}')
        db_subscriber.close()
        redis_client.close()
        sys.exit(-1)
