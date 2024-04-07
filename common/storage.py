#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros
#         vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz
"""
This module provides utilities for managing storage operations within
the Civilsphere AI VPN project. It includes functions for creating and managing
work directories based on profile names.

Functions:
    create_working_directory(profile_name): Creates a directory for a profile.
"""

import os
import configparser


def create_working_directory(profile_name):
    """
    Create a working directory to store files related with a profile_name.
    """
    try:
        # Read the file path to be used from config file
        config = configparser.ConfigParser()
        config.read('config/config.ini')
        storage_path = config['STORAGE']['PATH']

        profile_directory = storage_path+"/"+profile_name

        if not os.path.exists(profile_directory):
            os.makedirs(profile_directory)

        return True
    except KeyError as err:
        print(f"Configuration error: {err}")
        return False
    except OSError as err:
        print(f"File system error: {err}")
        return False
