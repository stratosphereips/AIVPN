#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN 
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import sys
import redis
import logging
import configparser
from common.database import *

def send_request_to_redis():
    """
    This function writes a new AI-VPN request to Redis.
    This is the first step to get a new account provisioned.
    """
    try:
        print("Sending a request to Redis")
        return True
    except Exception as e:
        print(e)

if __name__ == '__main__': 
    # Initialize logging
    logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.DEBUG,format='%(asctime)s, MOD_CONN_RECV, %(message)s')

    # Read configuration file
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_COMM_RECV_CHECK']
    LOG_FILE = config['LOGS']['LOG_COMM_RECV']
    IMAP_SERVER = config['IMAP']['SERVER']
    IMAP_USERNAME = config['IMAP']['USERNAME']
    IMAP_PASSWORD = config['IMAP']['PASSWORD']

    # Connecting to the Redis database
    try:
        db_publisher = redis_connect_to_db(REDIS_SERVER)
    except:
        logging.error("Unable to connect to the Redis database (",REDIS_SERVER,")")
        sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(db_publisher)
    except:
        logging.error("Unable to create a Redis subscriber")
        sys.exit(-1)

    # Subscribing to Redis channel
    try:
        redis_subscribe_to_channel(db_subscriber,CHANNEL)
    except:
        logging.error("Channel subscription failed")
        sys.exit(-1)
        
    try: 
        logging.info("Connection and channel subscription to redis successful.")

        # Checking for messages
        for item in db_subscriber.listen():
            if item['type'] == 'message':
                logging.info(item['channel'])
                logging.info(item['data'])
                if item['data'] == b'report_status':
                    # Check for new emails
                    # Load credentials
                    # check_new_requests()
                    #    - Parse the email to find valid requests (only VPN requests, etc)
                    # If there are new requests:
                    #    - Write request to REDIS with status PENDING (send_request_to_redis)
                    #    - Answer manager with message indicating there are new requests to process.
                    # If there are no new requests, report OK
                    db_publisher.publish('services_status', 'MOD_COMM_RECV:online')
                    logging.info('MOD_COMM_RECV:online')

        db_publisher.publish('services_status', 'MOD_COMM_RECV:offline')
        logging.info("Terminating.")
        db_publisher.close()
        db_subscriber.close()
        sys.exit(0)
    except Exception as err:
        db_publisher.close()
        db_subscriber.close()
        logging.info("Terminating via exception in main")
        logging.info(err)
        sys.exit(-1)
