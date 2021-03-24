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
                logging.error(e)
            try:
                COMMAND='/usr/local/bin/ovpn_initpki nopass <<'+PKI_INPUT
                logging.info(COMMAND)
                os.system(COMMAND)
            except Exception as e:
                logging.error(e)

            try:
                os.system('mkdir -p /dev/net')
            except Exception as e:
                logging.error(e)
                return False

            try:
                os.system('mknod /dev/net/tun c 10 200')
            except Exception as e:
                logging.error(e)
                return False

            try:
                os.system('chmod 600 /dev/net/tun')
            except Exception as e:
                logging.error(e)
                return False

            try:
                PROCESS = '/usr/sbin/openvpn --config /etc/openvpn/openvpn.conf --client-config-dir /etc/openvpn/ccd --crl-verify /etc/openvpn/pki/crl.pem'
                logging.info(PROCESS)
                subprocess.Popen(["/usr/sbin/openvpn","--config","/etc/openvpn/openvpn.conf","--client-config-dir","/etc/openvpn/ccd","--crl-verify","/etc/openvpn/pki/crl.pem"])
            except Exception as e:
                logging.error(e)

            return True
        else:
            return True
    except Exception as e:
        logging.error(e)
        return False

def generate_openvpn_profile(CLIENT_NAME):

    """
    This function generates a new profile for a client_name.
    """

    try:
        os.system('/usr/local/bin/easyrsa build-client-full %s nopass' % CLIENT_NAME)
        return True
    except exception as e:
        logging.error(e)
        return False

def get_openvpn_profile(CLIENT_NAME,CERTIFICATES):
    """
    This function returns the new generated client profile.
    """
    try:
        os.system('/usr/local/bin/ovpn_getclient %s > %s/%s.ovpn' % CLIENT_NAME,CERTIFICATES,CLIENT_NAME)
    except exception as e:
        logging.error(e)
        return False

if __name__ == '__main__':
    # Read configuration file
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_OPENVPN_CHECK']
    LOG_FILE = config['LOGS']['LOG_OPENVPN']
    SERVER_PUBLIC_URL = config['OPENVPN']['SERVER_PUBLIC_URL']
    PKI_ADDRESS = config['OPENVPN']['PKI_ADDRESS']
    CERTIFICATES = config['OPENVPN']['CERTIFICATES']
    NETWORK_CIDR = '192.168.0.0/24'

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
        logging.error("Unable to connect to the Redis database (",REDIS_SERVER,")")
        logging.error(f"Error {e}")
        sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(redis_client)
    except Exception as e:
        logging.error("Unable to create a Redis subscriber")
        logging.error(f"Error {e}")
        sys.exit(-1)

    # Subscribing to Redis channel
    try:
        redis_subscribe_to_channel(db_subscriber,CHANNEL)
        logging.info("Connection and channel subscription to redis successful.")
    except Exception as e:
        logging.error("Channel subscription failed")
        logging.error(f"Error {e}")
        sys.exit(-1)

    # Configuring the OpenVPN server
    if configure_openvpn_server(SERVER_PUBLIC_URL,PKI_ADDRESS):
        logging.info("OpenVPN Server is ready to be used")

    try:
        # Checking for messages
        logging.info("Listening for messages")
        for item in db_subscriber.listen():
            if item['type'] == 'message':
                logging.info(item['channel'])
                logging.info(item['data'])
                if item['data'] == b'report_status':
                    redis_client.publish('services_status', 'MOD_OPENVPN:online')
                    logging.info('MOD_OPENVPN:online')
                elif item['data'] == b'new_profile':
                    logging.info('MOD_OPENVPN:received request for a new profile')
                    redis_client.publish('services_status', 'MOD_OPENVPN:generating a new openvpn profile')
                    # Obtain IP address for client. If this cannot be done,
                    # exit and do not continue the process.
                    CLIENT_IP=openvpn_obtain_client_ip_address(NETWORK_CIDR)
                    if CLIENT_IP==False:
                        account_status=False
                        redis_client.publish('services_status','mod_openvpn: no IP addresses available. Process failed.')
                        redis_client.publish('provision_openvpn','profile_creation_failed')
                        logging.info('mod_openvpn: failed to create new openvpn profile, no IP addresses available.')
                    else:
                        # Parse the name obtained in the request
                        msg_account_name=item['data'].split(':')[1]
                        # Retrieve client name from Redis set
                        CLIENT_NAME = get_prov_generate_vpn(redis_client)
                        if msg_account_name == CLIENT_NAME:
                            result = generate_openvpn_profile(CLIENT_NAME)
                            if result:
                                result=add_profile_ip_relationship(CLIENT_NAME,CLIENT_IP)
                                #TODO: Write profile in the next provisioning queue
                                if result:
                                    redis_client.publish('services_status','MOD_OPENVPN: new profile generated')
                                    redis_client.publish('provision_openvpn','profile_creation_successful')
                                    logging.info('MOD_OPENVPN: new openvpn profile generated')
                            else:
                                account_status=False
                                redis_client.publish('services_status','mod_openvpn: failed to create a new profile')
                                redis_client.publish('provision_openvpn','profile_creation_failed')
                                logging.info('mod_openvpn: failed to create new openvpn profile')
                        else:
                            account_status=False
                            redis_client.publish('services_status','mod_openvpn: profile names did not match. Process failed.')
                            redis_client.publish('provision_openvpn','profile_creation_failed')
                            logging.info('mod_openvpn: failed to create new openvpn profile, profile names did not match.')
                    if account_status==False:
                        #TODO: write profile in the previous provisioning queue

        redis_client.publish('services_status', 'MOD_OPENVPN:offline')
        logging.info("Terminating")
        redis_client.close()
        db_subscriber.close()
        sys.exit(-1)
    except Exception as err:
        redis_client.close()
        db_subscriber.close()
        logging.info("Terminating via exception in main")
        logging.info(err)
        sys.exit(-1)
