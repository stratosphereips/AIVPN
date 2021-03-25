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
from common.storage import *

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

def redis_channel_monitoring(CHANNEL,db_subscriber,redis_client):
    while True:
        try:
            # Checking for messages
            for item in db_subscriber.listen():
                if item['type'] == 'message':
                    logging.info(item['channel'])
                    logging.info(item['data'])
                    if item['data'] == 'MOD_COMM_RECV:NEW_REQUEST':
                        try:
                            new_request = get_item_provisioning_queue(redis_client)
                            logging.info('New request received: {}'.format(new_request[0]))
                            result = provision_account(new_request[0],redis_client)
                            logging.info('Provisioning result: {}'.format(result))
                        except Exception as e:
                            logging.info(e)
        except:
            logging.info("Error in loop in thread services_status_monitor")
            db_subscriber = redis_create_subscriber(redis_client)
            redis_subscribe_to_channel(db_subscriber,CHANNEL)
            time.sleep(10)
            pass

def thread_redis_channel_status_check(MOD_CHANNELS,redis_client):
    """ """
    while True:
        try:
            logging.info("Sending report status message to: {}".format(MOD_CHANNELS))
            # send status check to every channel
            for channel in MOD_CHANNELS:
                logging.info("Sending report status message to: {}".format(channel))
                redis_client.publish(channel, 'report_status')
            time.sleep(60)
        except:
            logging.info("Error in loop in thread services_status_check")
            time.sleep(10)
            pass

def request_openvpn_profile(acc_profile_name,REDIS_CLIENT):

    """
    This function notifies the mod_openvpn that a new profile is needed.
    """
    channel='mod_openvpn_check'
    try:
        logging.info("Sending message to mod_openvpn")
        message='new_profile:'+acc_profile_name
        REDIS_CLIENT.publish(channel,message)
        return True
    except:
        logging.info("Error in loop in request_openvpn_profile")
        return False

def provision_account(new_request,REDIS_CLIENT):
    """ This function handles the steps needed to provision a new account."""

    # Step 0: Parse the new_request to extract values: msg_addr, msg_type, msg_id.
    ## new_request="msg_id":int(msg_id), "msg_type":str(msg_type), "msg_addr":str(msg_addr)
    new_request_object = json.loads(new_request)
    p_msg_addr = new_request_object['msg_addr']
    p_msg_id = new_request_object['msg_id']
    p_msg_type = new_request_object['msg_type']
    logging.info("Provisioning Step 0. Addr: {}, ID: {}, Type: {}".format(p_msg_addr,p_msg_id,p_msg_type))

    # Step 1: Can we provision this account? space, internet, PIDs, IPs, limits
    #         If we cannot, request is stored back in the provisioning queue.

    ## Check msg_addr hasn't reached the maximum limit of active profiles
    ## TODO: read limit from configuration file
    ACTIVE_ACCOUNT_LIMIT=2

    if get_active_profile_counter(p_msg_addr,REDIS_CLIENT) > ACTIVE_ACCOUNT_LIMIT:
        # New message sent to user saying the number of simultaneous accounts
        # has been reached. Try again later.
        pass

    ## TODO: Check if we have enough storage to provision the new account.

    ## TODO: Check if we have enough IP addresses to provision new account.

    logging.info("Provisioning Step 1 completed")
    # Step 2: Generate profile name. Store it. Create folder.

    ## Get an account name
    acc_profile_name = gen_profile_name()
    if not acc_profile_name:
        # Request is stored back in the provisioning queue.
        # Return error.
        return False
    logging.info("Profile name generated: {}".format(acc_profile_name))

    ## Store the mapping of profile_name:msg_addr to quickly know how to reach
    ## the user when the reports are finished, or a contact is needed.
    prov_status = add_profile_name(acc_profile_name,p_msg_addr,REDIS_CLIENT)
    if not prov_status:
        # Request is stored back in the previous queue
        # Return error
        return False

    logging.info("Mapping of profile_name:mst_addr was {}".format(prov_status))

    ## Store the mapping of msg_addr:profile_name to check for user usage limit.
    ## There will be a maximum number of accounts 
    prov_status = add_identity(p_msg_addr,REDIS_CLIENT)
    if prov_status:
        logging.info("Identity added successfully")
    else:
        logging.info("Identity already exists in Redis")

    ## Create a folder to store all files associated with the profile_name.
    ## The specific folder is specified in the configuration file.
    prov_status = create_working_directory(acc_profile_name)
    logging.info("Results of create_working_directory: {}".format(prov_status))
    if not prov_status:
        # Request is stored back in the previous queue
        # Return error
        return False

    ## Update identity table with new profile
    prov_status = upd_identity_profiles(p_msg_addr,acc_profile_name,REDIS_CLIENT)
    if prov_status is True:
        logging.info("upd_identity_profiles: success")
    else:
        # Request is stored back in the previous queue
        # Return error
        return False

    ## Store profile name to the next queue: prov_generate_vpn
    prov_status = add_prov_generate_vpn(acc_profile_name,REDIS_CLIENT)
    logging.info("add_prov_generate_vpn: {}".format(prov_status))

    # Step 3: Generate VPN Profile. OpenVPN or alternative.

    ## Trigger generation of VPN profile using profile_name.
    prov_status = request_openvpn_profile(acc_profile_name,REDIS_CLIENT)
    logging.info("request_openvpn_profile: {}".format(prov_status))

    # Wait for message from mod_openvpn that the generation is done
    # This wait is from a pub/sub channel dedicate for this step
    # Wait for message from mod_openvpn that the generation is done
    openvpn_subscriber = redis_create_subscriber(REDIS_CLIENT)
    redis_subscribe_to_channel(openvpn_subscriber,'provision_openvpn')
    item=openvpn_subscriber.listen()
    if item['type'] == 'message':
        if item['data'] == 'profile_creation_successful':
            #Good. Continue.
            logging.info("message from mod_openvpn: profile_creation_successful")
        if item['data'] == 'profile_creation_failed':
            #Bad. Roll back or try again.
            logging.info("message from mod_openvpn: profile_creation_failed")
            return False

    ## Retrieve from this process the client IP assigned to the profile_name.
    acc_profile_ip = get_ip_for_profile(acc_profile_name,REDIS_CLIENT)
    logging.info("get_ip_for_profile: {}".format(acc_profile_ip))

    # Step 4: Start traffic capture. Store PID.

    ## Get profile from the queue using profile_name as key

    ## Get IP address from list using profile_name as key

    ## Trigger start capturing for profile_name by mod_traffic_capture.
    ## Module will store a PID in Redis.

    ## Stores profile_name to the next queue: prov_send_profile

    # Step 5: Send profile or instruct manager to send profile.

    return True

if __name__ == '__main__':
    REDIS_SERVER = 'aivpn_mod_redis'
    MOD_CHANNELS = ['mod_comm_recv_check','mod_comm_send_check','mod_report_check','mod_traffic_capture_check','mod_openvpn_check']
    CHANNEL = 'services_status'
    LOG_FILE = '/logs/mod_manager.log'
    SWARM_CONF_FILE = '/code/common/swarm_modules.py'

    try:
        logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.DEBUG,format='%(asctime)s, MOD_MANAGER, %(message)s')
    except Exception as e:
        logging.info(e)
        sys.exit(-1)

    while not ( create_swarm_hosts_configuration_file(SWARM_CONF_FILE) ):
        logging.info("Unable to create Swarm hosts configuration file.")
        logging.info("Trying again")
        time.sleep(1)
    logging.info("Swarm hosts configuration file created successfully.")

    # Connecting to the Redis database
    try:
        redis_client = redis_connect_to_db(REDIS_SERVER)
    except Exception as e:
        logging.info("Unable to connect to the Redis database (",REDIS_SERVER,")")
        logging.info(e)
        sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(redis_client)
    except Exception as e:
        logging.info("Unable to create a Redis subscriber")
        logging.info(e)
        sys.exit(-1)

    # Subscribing to Redis channel
    try:
        redis_subscribe_to_channel(db_subscriber,CHANNEL)
    except Exception as e:
        logging.info("Channel subscription failed")
        logging.info(e)
        sys.exit(-1)

    # Main manager module logic starts here
    try:
        logging.info("Connection and channel subscription to redis successful.")
        redis_client.publish('services_status','MOD_MANAGER:online')

        # This thread sends status checks messages to modules
        services_status_check = threading.Thread(target=thread_redis_channel_status_check,args=(MOD_CHANNELS,redis_client,))
        services_status_check.start()
        logging.info("services_status_check thread started")

        # This function checks for incoming messages
        logging.info("Starting the services_status_monitor")
        while True:
            try:
                redis_channel_monitoring(CHANNEL,db_subscriber,redis_client)
            except Exception as e:
                logging.info("services_status_monitor restarting due to exception")
                logging.info(e)
                pass

        redis_client.publish('services_status', 'MOD_MANAGER:offline')
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
