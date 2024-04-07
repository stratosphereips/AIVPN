#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Sebastian Garcia,
#         eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz
# Author: Veronica Valeros
#         vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import os
import sys
import time
import logging
import configparser
import subprocess
import signal
import redis
from common.database import redis_connect_to_db
from common.database import redis_create_subscriber
from common.database import redis_subscribe_to_channel
from common.database import add_pid_profile_name_relationship
from common.database import add_profile_name_pid_relationship
from common.database import add_profile_ip_relationship
from common.database import get_vpn_client_ip_address


def revoke_profile(loc_profile):
    """
    Revoke a given profile using the 'del-peer' command.

    loc_profile (str): The local profile identifier for the profile to revoke.
    returns (bool): True if the profile was successfully revoked, else False.
    """
    action_status = False
    try:
        # Call the del-peer function using subprocess
        delpeer_result = subprocess.run(
                ['/app/del-peer', loc_profile],
                capture_output=True,
                text=True,
                check=True)
        # Return true only if the return code is 0
        if delpeer_result.returncode == 0:
            action_status = True
    except subprocess.CalledProcessError as loc_err:
        logging.error("del-peer failed, return code %s: %s",
                      loc_err.returncode,
                      loc_err.output)
    except OSError as loc_err:
        logging.error("del-peer failed with OSError: %s",
                      loc_err)
    except ValueError as loc_err:
        logging.error("del-peer failed, invalid arguments for subprocess: %s",
                      loc_err)

    # Return action_status for any of the cases
    return action_status


def generate_profile(loc_profile, loc_path, loc_client_ip):

    """
    This function generates a new profile for a client_name.

    loc_profile: profile name for the client
    loc_path: path were to store the profile
    loc_client_ip: IP assigned to the client
    """
    action_status = False
    try:
        # This is where we call the add-peer using subprocess
        addpeer_result = subprocess.run(
                ['/app/add-peer', loc_profile, loc_path, loc_client_ip],
                capture_output=True,
                text=True,
                check=True)
        if addpeer_result.returncode == 0:
            action_status = True
    except subprocess.CalledProcessError as loc_err:
        logging.error("add-peer failed, return code %s: %s",
                      loc_err.returncode,
                      loc_err.output)
    except OSError as loc_err:
        logging.error("add-peer failed with OSError: %s",
                      loc_err)
    except ValueError as loc_err:
        logging.error("add-peer failed, invalid arguments for subprocess: %s",
                      loc_err)

    # Return action_status for any of the cases
    return action_status


def start_traffic_capture(loc_profile, loc_client_ip, loc_path):
    """
    This function starts a tcpdump process to capture the traffic and store the
    pcap for a given client and IP.

    loc_profile: profile name for the client
    loc_client_ip: IP assigned to the client
    loc_path: path assigned to the client
    :return: The PID of the started tcpdump process or False on failure.

    """
    loc_pid = None

    # Identify which tcpdump to run
    try:
        cmd_tcpdump = os.popen('which tcpdump').read().strip()
    except OSError as loc_err:
        logging.error('Failed to find tcpdump: %s', loc_err)
        return False

    # Number used to differentiate pcaps if there's more than one
    pcap_number = str(time.monotonic()).split('.')[1]

    # Create the tcpdump file name
    profile_pcap_path = f'{loc_path}/{loc_profile}'
    profile_pcap_name = f'{loc_profile}_{loc_client_ip}_{pcap_number}.pcap'
    profile_file_path = f'{profile_pcap_path}/{profile_pcap_name}'

    # Prepare the arguments for the subprocess
    args = [cmd_tcpdump,
            "-qq",
            "-n",
            "-U",
            "-l",
            "-s0",
            "-i",
            "any",
            "host", loc_client_ip,
            "-w", profile_file_path]

    try:
        # Start the subprocess
        with subprocess.Popen(args,
                              start_new_session=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              stdin=subprocess.PIPE) as process:

            # Get the PID
            loc_pid = process.pid

    except ValueError:
        logging.error('Invalid arguments provided to subprocess.Popen')
    except OSError as loc_err:
        logging.error('OS error occurred: %s', loc_err)

    # Return the PID
    return loc_pid


def stop_traffic_capture(loc_client_pid):
    """
    Immediately stops the traffic capture process with the given PID.

    loc_client_pid (int): The PID of the traffic capture process to stop.
    :returns: True if the process was stopped successfully, False otherwise.
    """

    # Make sure we don't try to kill a non existent PID
    if loc_client_pid is None:
        logging.error("Invalid PID: None provided.")
        return False

    # Terminate the process immediately
    try:
        os.kill(loc_client_pid, signal.SIGKILL)
        # Wait for the process to be killed
        os.waitpid(loc_client_pid, 0)
        logging.info("Process with PID %d was killed.", loc_client_pid)
        return True
    except OSError as loc_err:
        logging.error('Failed to kill process with PID %d: %s',
                      loc_client_pid,
                      loc_err)
    except TypeError as loc_err:
        logging.error('Invalid PID type: %s', loc_err)
    return False


def read_configuration():
    """
    Read configuration values from the config file.
    """
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    redis_server = config['REDIS']['REDIS_SERVER']
    channel = config['REDIS']['REDIS_WIREGUARD_CHECK']
    log_file = config['LOGS']['LOG_WIREGUARD']
    server_public_url = config['WIREGUARD']['SERVER_PUBLIC_URL']
    pki_address = config['WIREGUARD']['PKI_ADDRESS']
    path = config['STORAGE']['PATH']

    return (redis_server, channel, log_file,
            server_public_url, pki_address, path)


if __name__ == '__main__':
    # Read configuration
    (REDIS_SERVER, CHANNEL, LOG_FILE,
     SERVER_PUBLIC_URL, PKI_ADDRESS, PATH) = read_configuration()

    # Initialize logging
    logging.basicConfig(filename=LOG_FILE,
                        level=logging.DEBUG,
                        format='%(asctime)s, MOD_WIREGUARD, %(message)s')

    try:
        # Connecting to the Redis database
        redis_client = redis_connect_to_db(REDIS_SERVER)

        # Creating a Redis subscriber and subscribing to channel
        db_subscriber = redis_create_subscriber(redis_client)
        redis_subscribe_to_channel(db_subscriber, CHANNEL)

    except redis.ConnectionError as err:
        logging.error('Connection error with Redis server (%s): %s',
                      REDIS_SERVER,
                      err)
        sys.exit(-1)
    except redis.TimeoutError as err:
        logging.error('Timeout error with Redis server (%s): %s',
                      REDIS_SERVER,
                      err)
        sys.exit(-1)
    except redis.AuthenticationError as err:
        logging.error('Authentication error with Redis server (%s): %s',
                      REDIS_SERVER,
                      err)
        sys.exit(-1)

    try:
        # Checking for messages
        logging.info("Listening for messages")
        for item in db_subscriber.listen():
            # Messages of other types are not processed at the moment
            if 'message' not in item['type']:
                continue

            # Every new type 'message' is processed and acted upon
            logging.info('New message received in channel %s: %s',
                         item['channel'],
                         item['data'])

            # Process all the scenarios of the new messages
            #  - report_status
            #  - new_profile
            #  - revoke_profile
            if 'report_status' in item['data']:
                redis_client.publish('services_status',
                                     'MOD_WIREGUARD:online')
                logging.info('Status Online')
                continue

            if 'new_profile' in item['data']:
                ACC_ERROR_MESSAGE = ""
                logging.info('Request to create new WireGuard profile')
                redis_client.publish('services_status',
                                     'MOD_WIREGUARD: processing new profile')

                # Get a client ip for wireguard
                CLIENT_IP = get_vpn_client_ip_address('wireguard',
                                                      redis_client)

                if CLIENT_IP is False:
                    ACC_ERROR_MESSAGE = "MOD_WIREGUARD: profile_creation_failed: no available IP addresses found"
                else:
                    # Parse the name obtained in the request
                    CLIENT_NAME = item['data'].split(':')[1]
                    redis_client.publish(
                            'services_status',
                            f'MOD_WIREGUARD: assigning IP ({CLIENT_IP}) to client ({CLIENT_NAME})')

                    # Generate the Wireguard profile for the client
                    logging.info('Generating WireGuard profile %s with IP %s',
                                 CLIENT_NAME,
                                 CLIENT_IP)
                    STATUS = generate_profile(CLIENT_NAME, PATH, CLIENT_IP)
                    if STATUS is True:
                        # Store client:ip relationship for the traffic capture
                        if add_profile_ip_relationship(CLIENT_NAME, CLIENT_IP, redis_client):
                            PID = start_traffic_capture(CLIENT_NAME, CLIENT_IP, PATH)
                            if PID is False:
                                ACC_ERROR_MESSAGE = "MOD_WIREGUARD: profile_creation_failed: cannot start tcpdump"
                            else:
                                logging.info('Tcpdump started successfully (PID:%s)', PID)
                                result = add_pid_profile_name_relationship(PID, CLIENT_NAME, redis_client)
                                result = add_profile_name_pid_relationship(CLIENT_NAME, PID, redis_client)
                                redis_client.publish('services_status',
                                                     'MOD_WIREGUARD:profile_creation_successful')
                                redis_client.publish('provision_wireguard',
                                                     'profile_creation_successful')
                                logging.info('profile_creation_successful')
                        else:
                            ACC_ERROR_MESSAGE = (
                                "MOD_WIREGUARD: profile_creation_failed:"
                                "cannot add profile_ip relationship to redis"
                            )
                    else:
                        ACC_ERROR_MESSAGE = "MOD_WIREGUARD: profile_creation_failed:failed to create a new profile"

                # Notify once if there is an error message
                if ACC_ERROR_MESSAGE:
                    logging.info(ACC_ERROR_MESSAGE)
                    redis_client.publish('services_status',
                                         ACC_ERROR_MESSAGE)
                    redis_client.publish('provision_wireguard',
                                         ACC_ERROR_MESSAGE)

            if 'revoke_profile' in item['data']:
                ACC_ERROR_MESSAGE = ""
                # Parse CLIENT_NAME and PID from message
                CLIENT_NAME = item['data'].split(':')[1]
                CLIENT_PID = int(item['data'].split(':')[2])
                logging.info('Request to revoke profile %s',
                             CLIENT_NAME)
                logging.info('Request to stop traffic capture (%s)',
                             CLIENT_PID)

                # Revoke VPN profile
                if revoke_profile(CLIENT_NAME):
                    # Stop the traffic capture by PID
                    STATUS = stop_traffic_capture(CLIENT_PID)
                    logging.info(
                            'Result of stopping the traffic capture was {%s}',
                            STATUS)
                    if STATUS:
                        # Account revoked successfully
                        redis_client.publish(
                                'services_status',
                                'MOD_WIREGUARD: profile_revocation_successful')
                        redis_client.publish(
                                'deprovision_wireguard',
                                'profile_revocation_successful')
                        logging.info('profile_revocation_successful')
                    else:
                        ACC_ERROR_MESSAGE = 'Cannot stop the traffic capture'
                else:
                    ACC_ERROR_MESSAGE = 'Cannot revoke the VPN profile.'

                # Notify once if there is an error message
                if ACC_ERROR_MESSAGE:
                    logging.info(ACC_ERROR_MESSAGE)
                    redis_client.publish('services_status',
                                         ACC_ERROR_MESSAGE)
                    redis_client.publish('deprovision_wireguard',
                                         ACC_ERROR_MESSAGE)

        redis_client.publish('services_status', 'MOD_WIREGUARD:offline')
        logging.info("Terminating")
        db_subscriber.close()
        redis_client.close()
        sys.exit(-1)
    except Exception as err:
        logging.info('Terminating via exception in main: %s', err)
        db_subscriber.close()
        redis_client.close()
        sys.exit(-1)
