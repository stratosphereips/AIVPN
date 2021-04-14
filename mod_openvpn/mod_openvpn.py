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
import time
import logging
import configparser
import ipaddress
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
            logging.info('Invoking the ovpn_run script to start the service')
            subprocess.Popen(["/usr/local/bin/ovpn_run"])
            return True
        except Exception as e:
            logging.info(e)
            return False

    except Exception as e:
        logging.info(e)
        return False

def revoke_openvpn_profile(CLIENT_NAME):
    """
    This function revokes a given profile.
    """
    try:
        COMMAND='/usr/local/bin/ovpn_revokeclient'
        subprocess.run([COMMAND,CLIENT_NAME], stdout=subprocess.PIPE, text=True, input="yes")
        return True
    except Exception as err:
        return err

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

def start_traffic_capture(CLIENT_NAME,CLIENT_IP,PATH):
    """
    This function starts a tcpdump process to capture the traffic and store the
    pcap for a given client and IP.
    """
    try:
        # Number used to differentiate pcaps if there's more than one
        NUMBER=str(time.monotonic()).split('.')[1]

        # Create the tcpdump file name
        PCAP_NAME=f'{PATH}/{CLIENT_NAME}/{CLIENT_NAME}_{CLIENT_IP}_{NUMBER}.pcap'

        # Start the subprocess
        process = subprocess.Popen(["tcpdump","-n","-s0","-i","tun0","host",CLIENT_IP,"-U","-w",PCAP_NAME],close_fds=True)

        # Get the PID
        PID = process.pid

        # Return the PID
        return PID
    except Exception as err:
        logging.info(f'Error in mod_openvpn::start_traffic_capture: {err}')
        return False

def stop_traffic_capture(CLIENT_PID):
    """ This function stops a given traffic capture by PID. """
    try:
        os.kill(CLIENT_PID,9)
        os.wait()
        return True
    except Exception as err:
        return err

def set_profile_static_ip(CLIENT_NAME,CLIENT_IP):
    """
    This function creates sets an static IP for the client profile by creating
    a file in the ccd/ directory with the IP set for the client.
    """
    try:
        # The IP configuration is stored in a file with the same name as the
        # OpenVPN client profile name in the client configuration directory.
        PATH = '/etc/openvpn/ccd/'
        FILE = PATH+CLIENT_NAME

        # The file should contain two IP addresses. The lower and upper limit
        # for the DHCP assignation. A difference of one between low and upper
        # limit forces the OpenVPN to assign static IPs to each client.
        CLIENT_IP_MAX = str(ipaddress.ip_address(CLIENT_IP)+1)
        CONFIGURATION = f'ifconfig-push {CLIENT_IP} {CLIENT_IP_MAX}'
        with open(FILE,'w') as writer:
            writer.write(CONFIGURATION)
        return True
    except Exception as err:
        logging.info(f'Exception in set_profile_static_ip: {err}')
        return False

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
                    CLIENT_IP=get_openvpn_client_ip_address(redis_client)
                    if not CLIENT_IP==False:
                        # Parse the name obtained in the request
                        CLIENT_NAME=item['data'].split(':')[1]
                        redis_client.publish('services_status',f'MOD_OPENVPN: assigning IP ({CLIENT_IP}) to client ({CLIENT_NAME})')
                        # Generate the openVPN profile for the client
                        if generate_openvpn_profile(CLIENT_NAME):
                            # Write the new profile to disk
                            get_openvpn_profile(CLIENT_NAME,PATH)
                            # Write the static IP address client configuration
                            set_profile_static_ip(CLIENT_NAME,CLIENT_IP)
                            # Store client:ip relationship for the traffic capture
                            if add_profile_ip_relationship(CLIENT_NAME,CLIENT_IP,redis_client):
                                PID = start_traffic_capture(CLIENT_NAME,CLIENT_IP,PATH)
                                if not PID == False:
                                    logging.info(f'Tcpdump started successfully (PID:{PID})')
                                    result = add_pid_profile_name_relationship(PID,CLIENT_NAME,redis_client)
                                    result = add_profile_name_pid_relationship(CLIENT_NAME,PID,redis_client)
                                    redis_client.publish('services_status','MOD_OPENVPN:profile_creation_successful')
                                    redis_client.publish('provision_openvpn','profile_creation_successful')
                                    logging.info('profile_creation_successful')
                                else:
                                    account_error_message="MOD_OPENVPN: profile_creation_failed:cannot start tcpdump"
                            else:
                                account_error_message="MOD_OPENVPN: profile_creation_failed:cannot add profile_ip relationship to redis"
                        else:
                            account_error_message="MOD_OPENVPN: profile_creation_failed:failed to create a new profile"
                    else:
                        account_error_message="MOD_OPENVPN: profile_creation_failed:no available IP addresses found"

                    # Notify once if there is an error message
                    if account_error_message:
                        logging.info(account_error_message)
                        redis_client.publish('services_status',account_error_message)
                        redis_client.publish('provision_openvpn',account_error_message)
                elif 'revoke_profile' in item['data']:
                    account_error_message=""
                    # Parse CLIENT_NAME and PID from message
                    CLIENT_NAME=item['data'].split(':')[1]
                    CLIENT_PID=int(item['data'].split(':')[2])
                    logging.info(f'Revoking profile {CLIENT_NAME} and stopping traffic capture ({CLIENT_PID})')

                    # Revoke VPN profile
                    if revoke_openvpn_profile(CLIENT_NAME):
                        # Stop the traffic capture by PID
                        status = stop_traffic_capture(CLIENT_PID)
                        logging.info(f'Result of stopping the traffic capture was {status}')
                        if status:
                            # Account revoked successfully
                            redis_client.publish('services_status','MOD_OPENVPN: profile_revocation_successful')
                            redis_client.publish('deprovision_openvpn','profile_revocation_successful')
                            logging.info('profile_revocation_successful')
                        else:
                            account_error_message='Unable to stop the traffic capture.'
                    else:
                        account_error_message='Unable to revoke the VPN profile.'

                    # Notify once if there is an error message
                    if account_error_message:
                        logging.info(account_error_message)
                        redis_client.publish('services_status',account_error_message)
                        redis_client.publish('deprovision_openvpn',account_error_message)

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
