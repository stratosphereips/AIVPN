#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import os
import configparser

# Read the file path to be used from config file
config = configparser.ConfigParser()
config.read('config/config.ini')
PATH = config['STORAGE']['PATH']

def create_working_directory(profile_name,PATH):
    """
    Create a working directory to store files related with a profile_name.
    """
    profile_directory = PATH+"/"+profile

    try:
        if not os.path.exists(profile_directory):
            os.makedirs(profile_directory)
        return True
    except OSError:
        return False

