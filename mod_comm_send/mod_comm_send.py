#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import sys
import redis
import logging
from common.database import *

if __name__ == '__main__':
    REDIS_SERVER = 'aivpn_mod_redis'
    CHANNEL = 'mod_comm_send_check'
    LOG_FILE = '/logs/mod_comm_send.log'

    try:
        logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.DEBUG,format='%(asctime)s, MOD_CONN_SEND, %(message)s')
    except:
        sys.exit(-1)

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
        db_publisher.publish('services_status', 'MOD_COMM_SEND:online')

        # Checking for messages
        for item in db_subscriber.listen():
            if item['type'] == 'message':
                logging.info(item['channel'])
                logging.info(item['data'])
                if item['data'] == 'report_status':
                    db_publisher.publish('services_status', 'MOD_COMM_SEND:online')

        db_publisher.publish('services_status', 'MOD_COMM_SEND:offline')
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
