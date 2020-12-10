#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN 
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import sys
import redis


def redis_connect_to_db(REDIS_SERVER):
    try:
        publisher = redis.Redis(REDIS_SERVER, port=6379, db=0)
        return publisher
    except Exception as err:
        return err

def redis_create_subscriber(publisher):
    try:
        subscriber = publisher.pubsub()
        return subscriber
    except Exception as err:
        return err

def redis_subscribe_to_channel(subscriber,CHANNEL):
    try:
        subscriber.subscribe(CHANNEL)
        return True
    except Exception as err:
        return err

if __name__ == '__main__': 
    REDIS_SERVER = 'aivpn_mod_redis'
    CHANNEL = 'mod_comm_recv_check'

    # Connecting to the Redis database
    try:
        db_publisher = redis_connect_to_db(REDIS_SERVER)
    except:
        print("Unable to connect to the Redis database (",REDIS_SERVER,")")
        sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(db_publisher)
    except:
        print("Unable to create a Redis subscriber")
        sys.exit(-1)

    # Subscribing to Redis channel
    try:
        redis_subscribe_to_channel(db_subscriber,CHANNEL)
    except:
        print("Channel subscription failed")
        sys.exit(-1)
        
    print("Connection and channel subscription to redis successful.")

    # Checking for messages
    for item in db_subscriber.listen():
        if item['type'] == 'message':
            print(item['channel'])
            print(item['data'])

    sys.exit(0)
