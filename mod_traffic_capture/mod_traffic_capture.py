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
    # Read configuration
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_TRAFFIC_CAPTURE_CHECK']
    LOG_FILE = config['LOGS']['LOG_TRAFFIC_CAPTURE']

    return REDIS_SERVER,CHANNEL,LOG_FILE

if __name__ == '__main__':
    REDIS_SERVER,CHANNEL,LOG_FILE = read_configuration()

    logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.DEBUG,format='%(asctime)s, MOD_TRAFFIC_CAPTURE, %(message)s')

    # Connecting to the Redis database. First to the address specified in the
    # configuration file. Second from the file created by the mod_manager.
    try:
        redis_client = redis_connect_to_db(REDIS_SERVER)
        logging.info("Connection to redis successful.")
    except Exception as err:
        try:
            from common.swarm_modules import *
            REDIS_SERVER=aivpn_mod_redis
        except Exception as err:
            logging.info(f'Exception in __main__: {err}. Cannot retrieve Redis IP: {REDIS_SERVER}')
            sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(redis_client)
        logging.info("Redis subscriber created.")
    except Exception as err:
        logging.info(f'Exception in __main__: {err}. Unable to create Redis subscriber.')
        sys.exit(-1)

    # Subscribing to Redis channel
    try:
        redis_subscribe_to_channel(db_subscriber,CHANNEL)
        logging.info("Subscribed to channel: {}".format(CHANNEL))
    except Exception as err:
        logging.info(f'Exception in __main__: {err}. Channel subscription failed.')
        sys.exit(-1)

    try:
        # Checking for messages
        logging.info("Listening for messages.")
        for item in db_subscriber.listen():
            if item['type'] == 'message':
                logging.info("New message received in channel {}: {}".format(item['channel'],item['data']))
                if item['data'] == 'report_status':
                    redis_client.publish('services_status', 'MOD_TRAFFIC_CAPTURE:online')
                    logging.info('MOD_TRAFFIC_CAPTURE:online')

        redis_client.publish('services_status', 'MOD_TRAFFIC_CAPTURE:offline')
        logging.info("Terminating")
        db_subscriber.close()
        redis_client.close()
        sys.exit(0)
    except Exception as err:
        logging.info("Exception in __main__: {}".format(err))
        db_subscriber.close()
        redis_client.close()
        sys.exit(-1)
