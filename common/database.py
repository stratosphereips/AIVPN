#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import redis

def redis_connect_to_db(REDIS_SERVER):
    """ Function to connect to a Redis database. Returns object publisher. """
    try:
        publisher = redis.Redis(REDIS_SERVER, port=6379, db=0)
        return publisher
    except Exception as err:
        return err

def redis_create_subscriber(publisher):
    """ Function to create a pubsub() object. Returns object subscriber. """
    try:
        subscriber = publisher.pubsub()
        return subscriber
    except Exception as err:
        return err

def redis_subscribe_to_channel(subscriber,CHANNEL):
    """ Function to subscribe a subscriber object to a given Redis channel"""
    try:
        subscriber.subscribe(channel)
        return true
    except exception as err:
        return err

# PROVISIONING QUEUE
## The provisioning queue is where new requests are queued before being handled.
## We receive many types of requests, through many types of messaging apps.
## One client can do many requests. 
## We store { "msg_id":45, "msg_type":"email", "msg_addr":"email@email.com" }

def add_item_provisioning_queue(REDIS_CLIENT,new_request):
    """ Function to add an item to the provisioning_queue Redis SET"""
    try:
        redis_set = "provisioning_queue"
        REDIS_CLIENT.zadd(redis_set,new_request)
        return true
    except exception as err:
        return err


def get_item_provisioning_queue(REDIS_CLIENT):
    """ Function to get an item from the provisioning_queue Redis SET"""
    try:
        return true
    except exception as err:
        return err

