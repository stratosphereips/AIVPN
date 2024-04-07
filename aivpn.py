#!/usr/bin/env python
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import re
import sys
import datetime
import argparse
import logging
from common.database import *


def manage_info(redis_client,profile_name):
    """
    Retrieve information about an AI VPN profile_name
    """
    try:
        logging.debug('Manage info: {profile_name}')
        vpn_type = get_profile_vpn_type(profile_name,redis_client)
        profile_creation_time = 'n/a'
        profile_expiration_time = 'n/a'
        profile_reported_time = 'n/a'
        profile_deletion_time = 'n/a'

        if exists_active_profile(profile_name,redis_client):
            profile_creation_time = datetime.datetime.fromtimestamp(float(get_active_profile_creation_time(profile_name,redis_client)))
            profile_active = 'active'
        else:
            profile_active = 'expired'
            profile_information = json.loads(get_expired_profile_information(profile_name,redis_client))
            try:
                profile_creation_time = datetime.datetime.fromtimestamp(float(profile_information['creation_time']))
            except:
                pass
            try:
                profile_expiration_time = datetime.datetime.fromtimestamp(float(profile_information['expiration_time']))
            except:
                pass
            try:
                profile_reported_time = datetime.datetime.fromtimestamp(float(profile_information['reported_time']))
            except:
                pass
            try:
                profile_deletion_time = datetime.datetime.fromtimestamp(float(profile_information['deletion_time']))
            except:
                pass

        print(f"[+] Profile information for: {profile_name}")
        print(f"   [-] Profile status: {profile_active}")
        print(f"   [-] VPN requested: {vpn_type}")
        print(f"   [-] Profile creation time: {profile_creation_time}")
        print(f"   [-] Profile expiration time: {profile_expiration_time}")
        print(f"   [-] Profile reported time: {profile_reported_time}")
        print(f"   [-] Profile deletion time: {profile_deletion_time}")
        pass
    except Exception as err:
        print(f'Exception in manage_info: {err}')

def manage_expire(redis_client, profile_name):
    """
    Add a profile to the force expire queue to deprovision
    """
    try:
        logging.debug(f'Manage expire: {profile_name}')
        if exists_active_profile(profile_name, redis_client):
            status = add_profile_to_force_expire(redis_client, profile_name)
            redis_client.publish('services_status', 'MOD_CLI:FORCE_EXPIRE')
            print(f"[+] Forced expiration on profile '{profile_name}' was '{status}'")
        else:
            print(f'[+] Profile already expired and processed')
    except Exception as err:
        print(f'Exception in manage_expire: {err}')


def manage_extend(profile_name):
    try:
        logging.debug(f'Manage extend: {profile_name}')
    except Exception as err:
        print(f'Exception in manage_extend: {err}')


def manage_whois(redis_client, profile_name):
    """
    Retrieve identity associated with a profile
    """
    try:
        identity = get_profile_name_address(profile_name, redis_client)
        logging.debug(f'Manage whois: {profile_name}')
        print(f"[+] User identity for {profile_name} is {identity}")
    except Exception as err:
        print(f'Exception in manage_whois: {err}')


def validate_identity(identity):
    """
    Verify the provided identity matches an email or telegram ID
    """
    try:
        email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        telegram_regex = r'\b[0-9]{8,}\b'
        if re.fullmatch(email_regex, identity):
            return "email"
        elif re.fullmatch(telegram_regex, identity):
            return "telegram"
        else:
            logging.debug(f"Identity must be a valid format (email or telegram ID): {identity}")
            return False
    except Exception as err:
        print(f'Exception in validate_identity: {err}')


def get_validated_data(identity):
    try:
        valid_identity = validate_identity(identity)
        return {
            "msg_id": 1,
            "msg_type": valid_identity,
            "msg_addr ": identity,
            "msg_request": ["openvpn", "wireguard", "novpn"]
        }

    except Exception as err:
        logging.debug(f"Identity {identity} is not valid")
        return f'Exception occurred in data validation for provision {err}'


def provision_openvpn(redis_client, identity):
    """
    Trigger the provisioning of a new OpenVPN profile for a client
    """
    identity_valid_data = get_validated_data(identity)
    logging.debug(f'Provision OpenVPN: {identity}')
    if identity_valid_data["msg_request"][0] and identity_valid_data["msg_type"]:
        # Add to provisioning queue
        status = add_item_provisioning_queue(redis_client, identity_valid_data["msg_id"], identity_valid_data["msg_type"],
                                             identity_valid_data["msg_addr"], identity_valid_data["msg_request"][0])
        redis_client.publish('services_status', 'MOD_COMM_RECV:NEW_REQUEST')
        print(
            f"Provisioning triggered: {status}. Number of items in the queue: {list_items_provisioning_queue(redis_client)}")
    else:
        print('Provisioning process failed, try again')


def provision_wireguard(redis_client, identity):
    """
    Trigger the provisioning of a new Wireguard profile for a client
    """
    valid_data = get_validated_data(identity)
    logging.debug(f'Provision Wireguard: {identity}')
    if valid_data["msg_request"][1] and valid_data["msg_type"]:
        # Add to provisioning queue
        status = add_item_provisioning_queue(redis_client, valid_data["msg_id"], valid_data["msg_type"],
                                             valid_data["msg_addr"], valid_data["msg_request"][1])
        redis_client.publish('services_status', 'MOD_COMM_RECV:NEW_REQUEST')
        print(
            f"Provisioning triggered: {status}. Number of items in the queue: {list_items_provisioning_queue(redis_client)}")
    else:
        print('Provisioning process failed, try again')


def provision_novpn(redis_client, identity):
    """
    Trigger the provisioning of a new not encrypted vpn profile for a client
    """
    valid_data = get_validated_data(identity)
    logging.debug(f'Provision No VPN: {identity}')
    if valid_data["msg_request"][2] and valid_data["msg_type"]:
        status = add_item_provisioning_queue(redis_client, valid_data["msg_id"], valid_data["msg_type"],
                                             valid_data["msg_addr"], valid_data["msg_request"][2])
        redis_client.publish('services_status', 'MOD_COMM_RECV:NEW_REQUEST')
        print(
            f"Provisioning triggered: {status}. Number of items in the queue: {list_items_provisioning_queue(redis_client)}")
    else:
        print('Provisioning process failed, try again')


def audit_active_profiles(redis_client, action):
    """
    Retrieve a list of active VPN profiles
    """
    try:
        logging.debug('Audit active profiles')
        active_profiles = get_active_profiles_keys(redis_client)
        print(f"[+] Number of active profiles: {len(active_profiles)}")
        if len(active_profiles) > 0:
            for profile in active_profiles:
                print(f"   [-] {profile}")
    except Exception as err:
        print(f'Exception in audit_active_profiles: {err}')


def audit_expired_profiles(redis_client, action):
    """
    Retrieve a list of expired profiles
    """
    try:
        logging.debug('Audit expired profiles')
        expired_profiles = get_expired_profiles_keys(redis_client)
        print(f"[+] Number of expired profiles: {len(expired_profiles)}")
        if len(expired_profiles) > 0:
            for profile in expired_profiles:
                print(f"   [-] {profile}")
    except Exception as err:
        print(f'Exception in audit_expired_profiles: {err}')


def audit_queued_profiles(redis_client, action):
    """
    Retrieve a list of profiles in provisioning queue
    """
    try:
        logging.debug('Audit queued profiles')
        queued_profiles = list_items_provisioning_queue(redis_client)
        print(f"[+] Number of queued profiles to provision: {queued_profiles}")
    except Exception as err:
        print(f'Exception in audit_expired_profiles: {err}')


if __name__ == '__main__':
    # Read configuration
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    MOD_CHANNELS = json.loads(config['REDIS']['REDIS_MODULES'])
    LOG_FILE = config['LOGS']['LOG_CLI']

    parser = argparse.ArgumentParser(description="AI VPN Command Line Tool")
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    parser.add_argument('--redis', help="AI VPN redis module IP address", required=True)

    # Configure commands
    subparser = parser.add_subparsers(dest='command')
    manage = subparser.add_parser('manage', help=f'Manage an AI VPN profile')
    provision = subparser.add_parser('provision', help=f'Provision a new AI VPN account')
    audit = subparser.add_parser('audit', help=f'Audit AI VPN activities')

    # manage actions
    manage.add_argument('--info', help='retrieve information of a profile', type=str, required=False,
                        metavar='<profile_name>')
    manage.add_argument('--expire', help='expire a profile', type=str, required=False, metavar='<profile_name>')
    manage.add_argument('--extend',
                        help='extend the expiration of a profile (add default expiration on top of current date)',
                        type=str, required=False, metavar='<profile_name>')
    manage.add_argument('--whois', help='retrieve identity associated with a profile', type=str, required=False,
                        metavar='<profile_name>')

    # provision actions
    provision.add_argument('--openvpn', help='create a new openvpn profile for a given identity', type=str,
                           required=False, metavar='<user email | user telegram>')
    provision.add_argument('--wireguard', help='create a new wireguard profile for a given identity', type=str,
                           required=False, metavar='<user email | user telegram>')
    provision.add_argument('--novpn', help='create a new novpn profile for a given identity', type=str, required=False,
                           metavar='<user email | user telegram>')

    # audit actions
    audit.add_argument('--profiles', choices=['active', 'expired', 'queued'], help='Audit profiles by type')

    args = parser.parse_args()

    # Setup logging
    if args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(filename=LOG_FILE, level=log_level, format='%(asctime)s, AIVPN_CLI, %(message)s')

    # parsing commands
    if args.command == 'manage':
        logging.info('Managing profile')
        if args.info:
            cli_action = manage_info
            params = args.info
        elif args.expire:
            cli_action = manage_expire
            params = args.expire
        elif args.extend:
            cli_action = manage_extend
            params = args.extend
        elif args.whois:
            cli_action = manage_whois
            params = args.whois

    if args.command == 'provision':
        logging.info('Provisioning account')
        if args.openvpn:
            cli_action = provision_openvpn
            params = args.openvpn
        elif args.wireguard:
            cli_action = provision_wireguard
            params = args.wireguard
        elif args.novpn:
            cli_action = provision_novpn
            params = args.novpn

    if args.command == 'audit':
        logging.info('Auditing AIVPN')
        if args.profiles == 'active':
            cli_action = audit_active_profiles
        elif args.profiles == 'expired':
            cli_action = audit_expired_profiles
        elif args.profiles == 'queued':
            cli_action = audit_queued_profiles
        params = args.profiles

    # Connecting to the Redis database
    try:
        redis_client = redis_connect_to_db(args.redis)
    except Exception as err:
        logging.info(f'Unable to connect to Redis ({args.redis}): {err}')
        sys.exit(-1)

    # Ensure action defined
    if 'cli_action' not in locals():
        parser.print_help()
        sys.exit(1)
        
    cli_action(redis_client,params)
