#!/bin/bash

# First generate the configuration of the vpn
/usr/local/bin/ovpn_genconfig -u udp://vpn.civilsphere.org 

# Generate the CA cert, and the key.
/usr/local/bin/ovpn_initpki nopass <<HERE
vpn.civilsphere.org
HERE

# Example of how to generate a client cert
/usr/local/bin/easyrsa build-client-full CLIENTNAME nopass
# And to retrieve it
/usr/local/bin/ovpn_getclient CLIENTNAME > /certs/CLIENTNAME1.ovpn

# Run now the python that manages the openvpn channel
python3 /code/mod_openvpn.py
