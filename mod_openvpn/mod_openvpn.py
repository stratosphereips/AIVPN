#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Sebastian Garcia
# - eldraco@gmail.com
# - sebastian.garcia@agents.fel.cvut.cz
# Author: Veronica Valeros
# - vero.valeros@gmail.com
# - veronica.valeros@aic.fel.cvut.cz

import os
import sys
import logging
import configparser
from common.database import *
import subprocess

def configure_openvpn_server(SERVER_PUBLIC_URL,PKI_ADDRESS):
    """
    This function checks if an OpenVPN server is configured.
    If it is not, then it configures it.
    """
    PKI_INPUT=""" HERE
              %s
              HERE""" % PKI_ADDRESS
    try:
        # If a certificate is not in the PKI folder, then we need to configure
        # the OpenVPN server.
        if not os.path.exists('/etc/openvpn/pki/crl.pem'):
            try:
                COMMAND='/usr/local/bin/ovpn_genconfig -u '+SERVER_PUBLIC_URL
                logging.info(COMMAND)
                os.system(COMMAND)
            except Exception as e:
                logging.info(e)
            try:
                COMMAND='/usr/local/bin/ovpn_initpki nopass <<'+PKI_INPUT
                logging.info(COMMAND)
                os.system(COMMAND)
            except Exception as e:
                logging.info(e)

        # Attempt to run the OpenVPN server
        try:
            logging.info("Setting up the environment variables for OpenVPN to run")
            os.environ['OPENVPN']='/etc/openvpn'
            os.environ['EASYRSA']='/usr/share/easy-rsa'
            os.environ['EASYRSA_CRL_DAYS']='3650'
            os.environ['EASYRSA_PKI']='/etc/openvpn/pki'
            #PROCESS = '/usr/sbin/openvpn --config /etc/openvpn/openvpn.conf --client-config-dir /etc/openvpn/ccd --crl-verify /etc/openvpn/pki/crl.pem'
            #subprocess.Popen(["/usr/sbin/openvpn","--config","/etc/openvpn/openvpn.conf","--client-config-dir","/etc/openvpn/ccd","--crl-verify","/etc/openvpn/pki/crl.pem"])
            logging.info('Invoking the ovpn_run script to start the service')
            subprocess.Popen(["/usr/local/bin/ovpn_run"])
            return True
        except Exception as e:
            logging.info(e)
            return False

    except Exception as e:
        logging.info(e)
        return False

def generate_openvpn_profile(CLIENT_NAME):

    """
    This function generates a new profile for a client_name.
    """

    try:
        os.system('/usr/local/bin/easyrsa build-client-full %s nopass' % CLIENT_NAME)
        return True
    except Exception as e:
        logging.info(e)
        return False

def get_openvpn_profile(CLIENT_NAME,PATH):
    """
    This function returns the new generated client profile.
    """
    try:
        os.system('/usr/local/bin/ovpn_getclient %s > %s/%s/%s.ovpn' % (CLIENT_NAME,PATH,CLIENT_NAME,CLIENT_NAME))
    except Exception as e:
        logging.info("Error in mod_openvpn::get_openvpn_profile: {}".format(e))

def read_configuration():
    # Read configuration file
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_OPENVPN_CHECK']
    LOG_FILE = config['LOGS']['LOG_OPENVPN']
    SERVER_PUBLIC_URL = config['OPENVPN']['SERVER_PUBLIC_URL']
    PKI_ADDRESS = config['OPENVPN']['PKI_ADDRESS']
    CERTIFICATES = config['OPENVPN']['CERTIFICATES']
    NETWORK_CIDR = config['OPENVPN']['NETWORK_CIDR']
    PATH = config['STORAGE']['PATH']

    return REDIS_SERVER,CHANNEL,LOG_FILE,SERVER_PUBLIC_URL,PKI_ADDRESS,CERTIFICATES,NETWORK_CIDR,PATH

if __name__ == '__main__':
    # Read configuration
    REDIS_SERVER,CHANNEL,LOG_FILE,SERVER_PUBLIC_URL,PKI_ADDRESS,CERTIFICATES,NETWORK_CIDR,PATH = read_configuration()

    try:
        #TODO: Fix encoding error.
        # logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.DEBUG,format='%(asctime)s, MOD_OPENVPN, %(message)s')
        logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG,format='%(asctime)s, MOD_OPENVPN, %(message)s')
    except Exception:
        sys.exit(-1)

    # Connecting to the Redis database
    try:
        redis_client = redis_connect_to_db(REDIS_SERVER)
    except Exception as e:
        logging.info("Unable to connect to the Redis database ({}): {}".format(REDIS_SERVER,e))
        sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(redis_client)
    except Exception as e:
        logging.info("Unable to create a Redis subscriber: {}".format(e))
        sys.exit(-1)

    # Subscribing to Redis channel
    try:
        redis_subscribe_to_channel(db_subscriber,CHANNEL)
        logging.info("Connection and channel subscription to redis successful.")
    except Exception as e:
        logging.info("Channel subscription failed: {}".format(e))
        sys.exit(-1)

    # Configuring the OpenVPN server
    if configure_openvpn_server(SERVER_PUBLIC_URL,PKI_ADDRESS):
        logging.info("OpenVPN Server is ready to be used")

    try:
        # Checking for messages
        logging.info("Listening for messages")
        for item in db_subscriber.listen():
            # Every new message is processed and acted upon
            if item['type'] == 'message':
                logging.info("New message received in channel {}: {}".format(item['channel'],item['data']))
                if item['data'] == 'report_status':
                    redis_client.publish('services_status', 'MOD_OPENVPN:online')
                    logging.info('Status: online')
                elif 'new_profile' in item['data']:
                    account_error_message=""
                    logging.info('Received a new request for an OpenVPN profile')
                    redis_client.publish('services_status', 'MOD_OPENVPN:processing a new OpenVPN profile')

                    # Obtaining an IP address for client is a must to move forward.
                    CLIENT_IP=openvpn_obtain_client_ip_address(NETWORK_CIDR,redis_client)
                    if not CLIENT_IP==False:
                        # Parse the name obtained in the request
                        CLIENT_NAME=item['data'].split(':')[1]
                        # Generate the openVPN profile for the client
                        result = generate_openvpn_profile(CLIENT_NAME)
                        if result:
                            # Write the new profile to disk
                            get_openvpn_profile(CLIENT_NAME,PATH)
                            # Store client:ip relationship for the traffic capture
                            result = add_profile_ip_relationship(CLIENT_NAME,CLIENT_IP,redis_client)
                            if result:
                                redis_client.publish('services_status','mod_openvpn:profile_creation_successful')
                                redis_client.publish('provision_openvpn','profile_creation_successful')
                                logging.info('profile_creation_successful')
                            else:
                                account_error_message="profile_creation_failed:cannot add profile_ip relationship to redis"
                        else:
                            account_error_message="profile_creation_failed:failed to create a new profile"
                    else:
                        account_error_message="profile_creation_failed:no available IP addresses found"

                    # Notify once if there is an error message
                    if account_error_message:
                        logging.info(account_error_message)
                        redis_client.publish('services_status',account_error_message)
                        redis_client.publish('provision_openvpn',account_error_message)
        redis_client.publish('services_status', 'MOD_OPENVPN:offline')
        logging.info("Terminating")
        redis_client.close()
        db_subscriber.close()
        sys.exit(-1)
    except Exception as err:
        redis_client.close()
        db_subscriber.close()
        logging.info("Terminating via exception in main: {}".format(err))
        sys.exit(-1)
