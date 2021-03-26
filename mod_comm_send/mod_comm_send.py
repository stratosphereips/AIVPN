#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import sys
import redis
import logging
import configparser
from common.database import *

def read_configuration():
    # Read configuration file
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_COMM_SEND_CHECK']
    LOG_FILE = config['LOGS']['LOG_COMM_SEND']
    IMAP_SERVER = config['IMAP']['SERVER']
    IMAP_USERNAME = config['IMAP']['USERNAME']
    IMAP_PASSWORD = config['IMAP']['PASSWORD']
    return REDIS_SERVER,CHANNEL,LOG_FILE,IMAP_SERVER,IMAP_USERNAME,IMAP_PASSWORD

if __name__ == '__main__':
    # Read configuration
    REDIS_SERVER,CHANNEL,LOG_FILE,IMAP_SERVER,IMAP_USERNAME,IMAP_PASSWORD = read_configuration()

    logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.DEBUG,format='%(asctime)s, MOD_COMM_SEND, %(message)s')

    # Connecting to the Redis database
    try:
        redis_client = redis_connect_to_db(REDIS_SERVER)
    except:
        logging.error("Unable to connect to the Redis database (",REDIS_SERVER,")")
        sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(redis_client)
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
                logging.info("New message received in channel {}: {}".format(item['channel'],item['data']))
                try:
                    msg_account_name=item['data'].split(':')[1]
                except:
                    msg_account_name=""
                if item['data'] == 'report_status':
                    redis_client.publish('services_status', 'MOD_COMM_SEND:online')
                    logging.info('MOD_COMM_SEND:online')
                elif 'send_openvpn_profile_email' in item['data'] and not msg_account_name=="":
                    logging.info('Sending OpenVPN profile to {}'.format(msg_account_name))
                elif 'send_expire_profile_email' in item['data'] and not msg_account_name=="":
                    logging.info('Sending expiration of profile to {}'.format(msg_account_name))
                elif 'send_report_profile_email' in item['data'] and not msg_account_name=="":
                    logging.info('Sending report on profile to {}'.format(msg_account_name))

        redis_client.publish('services_status', 'MOD_COMM_SEND:offline')
        logging.info("Terminating")
        redis_client.close()
        db_subscriber.close()
        sys.exit(0)
    except Exception as err:
        redis_client.close()
        db_subscriber.close()
        logging.info("Terminating via exception in main")
        logging.info(err)
        sys.exit(-1)
