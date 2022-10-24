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

    # Configure subparsers
    subparser = parser.add_subparsers(dest='command')
    manage = subparser.add_parser('manage')
    provision = subparser.add_parser('provision')
    audit = subparser.add_parser('audit')

    args = parser.parse_args()

    # Setup logging
    if args.verbose:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO
