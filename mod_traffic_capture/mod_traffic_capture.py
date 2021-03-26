#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import sys
import redis
import logging
import configparser
from common.database import *

if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_TRAFFIC_CAPTURE_CHECK']
    LOG_FILE = config['LOGS']['LOG_TRAFFIC_CAPTURE']

    try:
        logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.DEBUG,format='%(asctime)s, MOD_TRAFFIC_CAPTURE, %(message)s')
    except Exception as err:
        logging.info("Exception in __main__: {}".format(err))
        sys.exit(-1)

    try:
        from common.swarm_modules import *
        REDIS_SERVER=aivpn_mod_redis
    except Exception as err:
        logging.info("Exception in __main__: {}".format(err))
        logging.info("Cannot retrieve redis IP from manager")

    # Connecting to the Redis database
    try:
        db_publisher = redis_connect_to_db(REDIS_SERVER)
        logging.info("Connection to redis successful.")
    except Exception as err:
        logging.info("Exception in __main__: {}".format(err))
        logging.error("Unable to connect to the Redis database (",REDIS_SERVER,")")
        sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(db_publisher)
        logging.info("Redis subscriber created.")
    except Exception as err:
        logging.info("Exception in __main__: {}".format(err))
        logging.error("Unable to create a Redis subscriber")
        sys.exit(-1)

    # Subscribing to Redis channel
    try:
        redis_subscribe_to_channel(db_subscriber,CHANNEL)
        logging.info("Subscribed to channel: {}".format(CHANNEL))
    except Exception as err:
        logging.info("Exception in __main__: {}".format(err))
        logging.error("Channel subscription failed")
        sys.exit(-1)

    try:
        # Checking for messages
        logging.info("Listening for messages.")
        for item in db_subscriber.listen():
            logging.info(item)
            if item['type'] == 'message':
                logging.info("New message received in channel {}: {}".format(item['channel'],item['data']))
                if item['data'] == 'report_status':
                    db_publisher.publish('services_status', 'MOD_TRAFFIC_CAPTURE:online')
                    logging.info('MOD_TRAFFIC_CAPTURE:online')

        db_publisher.publish('services_status', 'MOD_TRAFFIC_CAPTURE:offline')
        logging.info("Terminating")
        db_publisher.close()
        db_subscriber.close()
        sys.exit(0)
    except Exception as err:
        logging.info("Exception in __main__: {}".format(err))
        db_publisher.close()
        db_subscriber.close()
        sys.exit(-1)
