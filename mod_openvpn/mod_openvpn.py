#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Sebastian Garcia
# - eldraco@gmail.com
# - sebastian.garcia@agents.fel.cvut.cz
# Author: Veronica Valeros
# - vero.valeros@gmail.com
# - veronica.valeros@aic.fel.cvut.cz

import sys
import logging
import configparser
from common.database import *

if __name__ == '__main__':
    # Read configuration file
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_OPENVPN_CHECK']
    LOG_FILE = config['LOGS']['LOG_OPENVPN']

    try:
        #logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.DEBUG,format='%(asctime)s, MOD_OPENVPN, %(message)s')
        logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG,format='%(asctime)s, MOD_OPENVPN, %(message)s')
    except Exception:
        sys.exit(-1)

    # Connecting to the Redis database
    try:
        db_publisher = redis_connect_to_db(REDIS_SERVER)
    except Exception as e:
        logging.error("Unable to connect to the Redis database (",REDIS_SERVER,")")
        logging.error(f"Error {e}")
        sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(db_publisher)
    except Exception as e:
        logging.error("Unable to create a Redis subscriber")
        logging.error(f"Error {e}")
        sys.exit(-1)

    # Subscribing to Redis channel
    try:
        redis_subscribe_to_channel(db_subscriber,CHANNEL)
    except Exception as e:
        logging.error("Channel subscription failed")
        logging.error(f"Error {e}")
        sys.exit(-1)

    try:
        logging.info("Connection and channel subscription to redis successful.")

        # Checking for messages
        for item in db_subscriber.listen():
            if item['type'] == 'message':
                logging.info(item['channel'])
                logging.info(item['data'])
                if item['data'] == b'report_status':
                    db_publisher.publish('services_status', 'MOD_OPENVPN:online')
                    logging.info('MOD_OPENVPN:online')

        db_publisher.publish('services_status', 'MOD_OPENVPN:offline')
        logging.info("Terminating")
        db_publisher.close()
        db_subscriber.close()
        sys.exit(0)
    except Exception as err:
        db_publisher.close()
        db_subscriber.close()
        logging.info("Terminating via exception in main")
        logging.info(err)
        sys.exit(-1)
