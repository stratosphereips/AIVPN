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
import configparser
from common.database import *
from common.storage import *

def read_configuration():
    # Read configuration file
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_MANAGER_CHECK']
    LOG_FILE = config['LOGS']['LOG_MANAGER']
    PATH = config['STORAGE']['PATH']
    SWARM_CONF_FILE = config['STORAGE']['SWARM_CONF_FILE']
    MOD_CHANNELS = json.loads(config['REDIS']['REDIS_MODULES'])
    return REDIS_SERVER,CHANNEL,LOG_FILE,PATH,SWARM_CONF_FILE,MOD_CHANNELS

def redis_channel_monitoring(CHANNEL,db_subscriber,redis_client):
    while True:
        try:
            # Checking for messages
            for item in db_subscriber.listen():
                if item['type'] == 'message':
                    logging.info("New message received in channel {}: {}".format(item['channel'],item['data']))
                    if item['data'] == 'MOD_COMM_RECV:NEW_REQUEST':
                        try:
                            new_request = get_item_provisioning_queue(redis_client)
                            logging.info('New request received: {}'.format(new_request[0]))
                            result = provision_account(new_request[0],redis_client)
                            logging.info('Provisioning result: {}'.format(result))
                        except Exception as e:
                            logging.info(e)
        except Exception as err:
            logging.info(f'Error in loop in thread services_status_monitor: {err}')
            db_subscriber = redis_create_subscriber(redis_client)
            redis_subscribe_to_channel(db_subscriber,CHANNEL)
            time.sleep(2)
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

def provision_account(new_request,REDIS_CLIENT):
    """ This function handles the steps needed to provision a new account."""

    # Step 0: Parse the new_request to extract values: msg_addr, msg_type, msg_id.
    ## new_request="msg_id":int(msg_id), "msg_type":str(msg_type), "msg_addr":str(msg_addr)
    new_request_object = json.loads(new_request)
    p_msg_addr = new_request_object['msg_addr']
    p_msg_id = new_request_object['msg_id']
    p_msg_type = new_request_object['msg_type']
    logging.info("Provisioning: new account for {} (ID: {}, Type: {})".format(p_msg_addr,p_msg_id,p_msg_type))

    # Step 1: Can we provision this account? space, internet, PIDs, IPs, limits
    #         If we cannot, request is stored back in the provisioning queue.

    ## TODO: read limit from configuration file
    ACTIVE_ACCOUNT_LIMIT=300

    ## Check msg_addr hasn't reached the maximum limit of active profiles
    acc_number_active_profiles = get_active_profile_counter(p_msg_addr,REDIS_CLIENT)
    logging.info(f'Provisioning: number of active profiles for {p_msg_addr}: {acc_number_active_profiles}')
    if acc_number_active_profiles > ACTIVE_ACCOUNT_LIMIT:
        # Send message to user notifying limit has been reached. Discard request.
        logging.info(f'Provisioning: user exceeded the number of active profiles.')
        REDIS_CLIENT.publish('mod_comm_send_check','error_limit_reached:'+p_msg_addr)
        return False

    ## TODO: Check if we have enough storage to provision the new account.

    ## Check if we have enough IP addresses to provision new account.
    available_ips=get_openvpn_free_ip_address_space(REDIS_CLIENT)
    logging.info(f'Provisioning: number of available IPs: {available_ips}')
    if available_ips<1:
        # Send message notifying the AI VPN is at full capacity. Discard request.
        logging.info(f'Provisioning: not enough ip addresses available to provision {p_msg_addr}')
        redis_client.publish('mod_comm_send_check','error_max_capacity:'+p_msg_addr)
        return False

    # Step 2: Generate profile name. Store it. Create folder.
    ## Get an account name
    acc_profile_name = gen_profile_name()
    logging.info("Provisioning: profile name reserved {}".format(acc_profile_name))
    if not acc_profile_name:
        # Request is stored back in the provisioning queue.
        add_item_provisioning_queue(REDIS_CLIENT,p_msg_id,p_msg_type,p_msg_addr)
        logging.info(f'Provisioning: unable to provision, rolling back.')
        return False

    ## Store the mapping of profile_name:msg_addr to quickly know how to reach
    ## the user when the reports are finished, or a contact is needed.
    prov_status = add_profile_name(acc_profile_name,p_msg_addr,REDIS_CLIENT)
    logging.debug("Provisioning: Mapping of profile_name:mst_addr was {}".format(prov_status))
    if not prov_status:
        # Request is stored back in the provisioning queue.
        add_item_provisioning_queue(REDIS_CLIENT,p_msg_id,p_msg_type,p_msg_addr)
        logging.info(f'Provisioning: unable to provision, rolling back.')
        return False

    ## Create a folder to store all files associated with the profile_name.
    ## The specific folder is specified in the configuration file.
    prov_status = create_working_directory(acc_profile_name)
    logging.info("Provisioning: creation of working directory was {}".format(prov_status))
    if not prov_status:
        # Request is stored back in the provisioning queue.
        add_item_provisioning_queue(REDIS_CLIENT,p_msg_id,p_msg_type,p_msg_addr)
        logging.info(f'Provisioning: unable to provision, rolling back.')
        return False

    # Step 3-4: Generate VPN Profile. OpenVPN or alternative.
    #           Start traffic capture. Store PID.

    ## Trigger generation of VPN profile using profile_name.
    message='new_profile:'+acc_profile_name
    REDIS_CLIENT.publish('mod_openvpn_check',message)
    logging.info("Provisioning: requested mod_openvpn a new profile.")

    # Wait for message from mod_openvpn that the generation is done
    # This wait is from a pub/sub channel dedicate for this step
    openvpn_subscriber = redis_create_subscriber(REDIS_CLIENT)
    redis_subscribe_to_channel(openvpn_subscriber,'provision_openvpn')
    for item in openvpn_subscriber.listen():
        if item['type'] == 'message':
            logging.info("Provisioning: {}".format(item['data']))
            if 'profile_creation_successful' in item['data']:
                #Good. Continue.
                break
            if 'profile_creation_failed' in item['data']:
                # Send message to user notifying the AI VPN is at full capacity.
                message=item['data']
                logging.info(f'provisioning: {message}')
                if 'no available IP' in message:
                    redis_client.publish('mod_comm_send_check','error_max_capacity:'+p_msg_addr)
                else:
                    # Request is stored back in the provisioning queue.
                    add_item_provisioning_queue(REDIS_CLIENT,p_msg_id,p_msg_type,p_msg_addr)
                    logging.info(f'Provisioning: unable to provision, rolling back.')
                return False

    # Step 5: Send profile or instruct manager to send profile.
    REDIS_CLIENT.publish('mod_comm_send_check','send_openvpn_profile_email:'+acc_profile_name)

    # Step 6: Provisioning successful, update Redis with account information.
    # If there's an error, these structures are not updated.

    ## Create identity for the account address.
    prov_status = add_identity(p_msg_addr,REDIS_CLIENT)
    logging.info("Provisioning: result of adding new identity was {}".format(prov_status))

    ## Update identity: add profile_name to account identity.
    prov_status = upd_identity_profiles(p_msg_addr,acc_profile_name,REDIS_CLIENT)
    logging.info("Provisioning: identity profile update was {}".format(prov_status))

    ## Update identity: increase identity counter by one.
    prov_status = upd_identity_counter(p_msg_addr,REDIS_CLIENT)

    # Increase the profile counter for the account address
    prov_status = add_active_profile_counter(p_msg_addr,REDIS_CLIENT)

    # Add the profile to the list of AIVPN active profiles
    prov_status = add_active_profile(acc_profile_name,REDIS_CLIENT)

    # Close the redis subscriber we created
    openvpn_subscriber.close()
    return True

def process_expired_accounts(REDIS_CLIENT,EXPIRATION_THRESHOLD):
    """ Checks for new accounts to expire, and deprovisions them. """
    try:
        # Get a list of active profiles to expire
        to_expire_profiles = get_active_profiles_to_expire(EXPIRATION_THRESHOLD,REDIS_CLIENT)
        logging.info(f'Processing {len(to_expire_profiles} expired accounts.')

        if to_expire_profiles:
            for profile_name in to_expire_profiles:
                deprovision_account(profile_name,REDIS_CLIENT)
        return True
    except Exception as err:
        return err

def deprovision_account(profile_name,REDIS_CLIENT):
    """
    This function handles all the necessary steps to deprovision an account,
    including revoking the VPN profile and stopping the traffic captures.
    """
    try:
        # Get account information
        acc_msg_addr = get_profile_name_address(profile_name,REDIS_CLIENT)
        acc_active_pid = get_profile_name_pid_relationship(profile_name,REDIS_CLIENT)
        acc_ip_addr = get_ip_for_profile(profile_name,REDIS_CLIENT)

        # Send mod_openvpn message to deprovision an account
        message = f'revoke_profile:{profile_name}:{acc_active_pid}'
        REDIS_CLIENT.publish('mod_openvpn_check',message)
        logging.info("Provisioning: requested mod_openvpn a new profile.")

        # Wait for message from mod_openvpn that the account was revoked.
        # Wait in a dedicated pub/sub channel: deprovision_openvpn
        openvpn_subscriber = redis_create_subscriber(REDIS_CLIENT)
        redis_subscribe_to_channel(openvpn_subscriber,'deprovision_openvpn')
        for item in openvpn_subscriber.listen():
            if item['type'] == 'message':
                logging.info("Deprovisioning: {}".format(item['data']))
                if 'profile_revocation_successful' in item['data']:
                    # Good. Continue.
                    break
                if 'profile_revocation_failed' in item['data']:
                    # Bad. Try again.
                    return False

        # Remove profile from the list of active profiles
        status = del_active_profile(profile_name,REDIS_CLIENT)

        # Remove IP from list of OpenVPN blocked IPs
        status = del_ip_address(acc_ip_addr,REDIS_CLIENT)

        # Remove PID<->Profile_Name relationships
        status = del_pid_profile_name_relationship(acc_active_pid,REDIS_CLIENT)
        status = del_profile_name_pid_relationship(profile_name,REDIS_CLIENT)

        # Decrease the active profile counter for the user
        status = subs_active_profile_counter(acc_msg_addr,REDIS_CLIENT)

        # Add profile to expired_profiles 

        return True
    except Exception as err
        return err

if __name__ == '__main__':
    REDIS_SERVER,CHANNEL,LOG_FILE,PATH,SWARM_CONF_FILE,MOD_CHANNELS = read_configuration()
    try:
        logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.DEBUG,format='%(asctime)s, MOD_MANAGER, %(message)s')
    except Exception as e:
        logging.info(e)
        sys.exit(-1)

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
