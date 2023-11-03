#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros
#         vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz
"""
Processes network traffic profiles using Slips IDS and interacts with Redis.

This module reads network packet captures from specified profile directories,
processes them with Slips IDS. It communicates the status via Redis channels.

Functions:
    process_profile_traffic(profile_name, storage_path):
        Runs Slips IDS on pcap files for the given profile.

The script's main section handles Redis connection, subscription,
and message-driven processing workflow.
"""

import os
import sys
import glob
import logging
import redis
import subprocess
import configparser
from common.database import redis_connect_to_db
from common.database import redis_create_subscriber
from common.database import redis_subscribe_to_channel


def process_profile_traffic(profile_name, storage_path):
    """
    Process the traffic for a given profile with Slips IDS.
    """

    try:
        # Go to profile directory
        os.chdir(f'{storage_path}/{profile_name}')

        # Find all pcaps for the profile and process them
        for capture_file in glob.glob("*.pcap"):
            # Check size of packet capture
            capture_size = os.stat(capture_file).st_size
            logging.info('Processing file: %s (%s b)',
                         capture_file,
                         capture_size)

            # If capture is empty: do not process it
            if capture_size < 26:
                return False

            # If capture is not empty, process it with Slips IDS
            profile_filename = f'{storage_path}/{profile_name}/{capture_file}'
            slips_output = f'{storage_path}/{profile_name}/slips_{capture_file}/'
            slips_config = '/StratosphereLinuxIPS/aivpn_slips.conf'

            # Create Slips working directory
            os.mkdir(f'{storage_path}/{profile_name}/slips_{capture_file}')

            # Run Slips as subprocess
            args = ['/StratosphereLinuxIPS/slips.py',
                    '-c', slips_config,
                    '-f', profile_filename,
                    '-o', slips_output]
            subprocess.run(args,
                           cwd="/StratosphereLinuxIPS",
                           stdout=subprocess.PIPE,
                           timeout=86400,
                           check=True)

        # When all captures are processed, return True
        return True
    except FileNotFoundError as pptf_error:
        logging.error(
            'File not found at process_profile_traffic: %s',
            pptf_error
        )
        return False
    except PermissionError as pptf_error:
        logging.error(
            'Permission error at process_profile_traffic: %s',
            pptf_error
        )
        return False
    except IsADirectoryError as pptf_error:
        logging.error(
            'Expected file found dir at process_profile_traffic: %s',
            pptf_error
        )
        return False
    except NotADirectoryError as pptf_error:
        logging.error(
            'Expected dir found file at process_profile_traffic: %s',
            pptf_error
        )
        return False
    except subprocess.TimeoutExpired as pptf_error:
        logging.error(
            'Subprocess timed out at process_profile_traffic: %s',
            pptf_error
        )
        return False
    except subprocess.CalledProcessError as pptf_error:
        logging.error(
            'Subprocess exited with error at process_profile_traffic: %s',
            pptf_error
        )
        return False
    except OSError as pptf_error:
        logging.error(
            'OS error at process_profile_traffic: %s',
            pptf_error
        )
        return False
    except Exception as pptf_error:
        logging.error(
            'Unexpected exception at process_profile_traffic: %s',
            pptf_error
        )
        return False


if __name__ == '__main__':
    # Read configuration
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_SLIPS_CHECK']
    LOG_FILE = config['LOGS']['LOG_SLIPS']
    storage_path = config['STORAGE']['PATH']

    logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG,
                        format='%(asctime)s, MOD_SLIPS, %(message)s')

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
    except Exception as err:
        logging.error('Unexpected error during Redis operations: %s',
                      err)
        sys.exit(-1)

    try:
        # Starting Slips Redis Database
        subprocess.Popen(['redis-server', '--daemonize', 'yes'])
    except subprocess.SubprocessError as err:
        logging.error(
                'Subprocess error while starting Slips Redis database: %s',
                err)
        sys.exit(-1)
    except Exception as err:
        logging.error(
                'Unexpected error while starting Slips Redis database: %s',
                err)
        sys.exit(-1)

    try:
        logging.info("Successful Redis connection and subscription.")

        # Checking for messages
        for item in db_subscriber.listen():
            if item['type'] == 'message':
                logging.info("New message in channel %s: %s",
                             item['channel'],
                             item['data'])
                if item['data'] == 'report_status':
                    redis_client.publish('services_status', 'MOD_SLIPS:online')
                    logging.info('MOD_SLIPS:online')
                elif 'process_profile' in item['data']:
                    profile_name = item['data'].split(':')[1]
                    logging.info('Running Slips on profile %s', profile_name)
                    STATUS = process_profile_traffic(profile_name, storage_path)
                    logging.info('Slips analysis on %s: %s', profile_name, STATUS)
                    if not STATUS:
                        logging.info('Error running Slips on profile')
                        message = f'slips_false:{profile_name}'
                        redis_client.publish('slips_processing', message)
                        continue
                    if STATUS:
                        logging.info('Slips analysis completed')
                        message = f'slips_true:{profile_name}'
                        redis_client.publish('slips_processing', message)

        redis_client.publish('services_status', 'MOD_SLIPS:offline')
        logging.info("Terminating")
        db_subscriber.close()
        redis_client.close()
        sys.exit(0)
    except Exception as err:
        logging.info('Terminating via exception in __main__: %s', err)
        db_subscriber.close()
        redis_client.close()
        sys.exit(-1)
