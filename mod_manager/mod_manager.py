#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import sys
import time
import json
import redis
import socket
import logging
import threading
from common.database import *

def create_swarm_hosts_configuration_file(SWARM_CONF_FILE):
    MODULES = ['aivpn_mod_redis']
    try:
        f = open(SWARM_CONF_FILE, 'w')
        for mod in MODULES:
            try:
                f.write(mod+'=\''+socket.gethostbyname(mod)+'\'\n')
            except:
                f.close()
                return False
        f.close()
        return True
    except Exception as err:
        return False

def thread_redis_channel_monitoring(CHANNEL,db_subscriber,db_publisher):
    while True:
        try:
            # Checking for messages
            for item in db_subscriber.listen():
                if item['type'] == 'message':
                    logging.info(item['channel'])
                    logging.info(item['data'])
                    if item['data'] == b'MOD_COMM_RECV:NEW_REQUEST':
                        new_request = get_item_provisioning_queue(db_publisher)
                        logging.info(new_request)
        except:
            logging.info("Error in loop in thread services_status_monitor")
            db_subscriber = redis_create_subscriber(db_publisher)
            redis_subscribe_to_channel(db_subscriber,CHANNEL)
            time.sleep(10)
            pass

def thread_redis_channel_status_check(MOD_CHANNELS,db_publisher):
    while True:
        try:
            logging.info("Sending report status message to: ",MOD_CHANNELS)
            # send status check to every channel
            for channel in MOD_CHANNELS:
                logging.info("Sending report status message to: ",channel)
                db_publisher.publish(channel, 'report_status')
            time.sleep(60)
        except:
            logging.info("Error in loop in thread services_status_check")
            time.sleep(10)
            pass

if __name__ == '__main__':
    REDIS_SERVER = 'aivpn_mod_redis'
    MOD_CHANNELS = ['mod_report_check','mod_comm_send_check','mod_comm_recv_check','mod_comm_send_check','mod_traffic_capture_check']
    CHANNEL = 'services_status'
    LOG_FILE = '/logs/mod_manager.log'
    SWARM_CONF_FILE = '/code/common/swarm_modules.py'

    try:
        logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.DEBUG,format='%(asctime)s, MOD_MANAGER, %(message)s')
    except:
        sys.exit(-1)

    while not ( create_swarm_hosts_configuration_file(SWARM_CONF_FILE) ):
        logging.info("Unable to create Swarm hosts configuration file.")
        logging.info("Trying again")
        time.sleep(1)
    logging.info("Swarm hosts configuration file created successfully.")

    # Connecting to the Redis database
    try:
        db_publisher = redis_connect_to_db(REDIS_SERVER)
    except:
        logging.info("Unable to connect to the Redis database (",REDIS_SERVER,")")
        sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(db_publisher)
    except:
        logging.info("Unable to create a Redis subscriber")
        sys.exit(-1)

    # Subscribing to Redis channel
    try:
        redis_subscribe_to_channel(db_subscriber,CHANNEL)
    except:
        logging.info("Channel subscription failed")
        sys.exit(-1)

    # Main manager module logic starts here
    try:
        logging.info("Connection and channel subscription to redis successful.")
        db_publisher.publish('services_status', 'MOD_MANAGER:online')


        # This thread checks for incoming messages
        services_status_monitor = threading.Thread(target=thread_redis_channel_monitoring,args=(CHANNEL,db_subscriber,db_publisher,))
        services_status_monitor.start()
        logging.info("services_status_monitor thread started")

        # This thread checks for incoming messages
        services_status_check = threading.Thread(target=thread_redis_channel_status_check,args=(MOD_CHANNELS,db_publisher,))
        services_status_check.start()
        logging.info("services_status_check thread started")

        time.sleep(3600)
        db_publisher.publish('services_status', 'MOD_MANAGER:offline')
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
