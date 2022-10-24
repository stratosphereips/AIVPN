#!/usr/bin/env python
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import sys
import argparse
import logging
import configparser
from common.database import *

if __name__ == '__main__':
    # Read configuration
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    MOD_CHANNELS = json.loads(config['REDIS']['REDIS_MODULES'])

    parser = argparse.ArgumentParser(description = "AI VPN Command Line Tool")
    parser.add_argument( "-v", "--verbose", help="increase output verbosity", action="store_true")

    # Configure commands
    subparser = parser.add_subparsers(dest='command')
    manage = subparser.add_parser('manage')
    provision = subparser.add_parser('provision')
    audit = subparser.add_parser('audit')

    # manage actions
    manage.add_argument('--info', help='retrieve information of a profile', type=str, required=True)
    manage.add_argument('--expire', help='expire a profile', type=str, required=True)
    manage.add_argument('--extend', help='extend the expiration of a profile (add default expiration on top of current date)', type=str, required=True)
    manage.add_argument('--whois', help='retrieve identity associated with a profile', type=str, required=True)

    # provision actions
    provision.add_argument('--new-openvpn', help='create a new openvpn profile for a given identity (email|telegram)', type=str, required=True)
    provision.add_argument('--new-wireguard', help='create a new wireguard profile for a given identity (email|telegram)', type=str, required=True)
    provision.add_argument('--new-novpn', help='create a new novpn profile for a given identity (email|telegram)', type=str, required=True)

    # audit actions
    audit.add_argument('--active-profiles', help='list all AI VPN active profiles', type=str, required=True)
    audit.add_argument('--expired-profiles', help='list all AI VPN expired profiles', type=str, required=True)

    args = parser.parse_args()

    # Setup logging
    if args.verbose:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO
