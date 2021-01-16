# To execute
# This is supposedly running alone 
docker build -t aivpn_mod_openvpn:latest

# This is what needs to be run now in order to work
docker run -dit -v $(pwd)/certs:/certs aivpn_mod_openvpn /bin/bash /code/mod_comm_openvpn.sh

# Issues:
- Everytime the docker starts it generates a new CA cert and key. This is bad if you want the former clients to connect to this vpn. Ideally this should be generated only once
- The request for new clients certs should be done by the python when a message arrives in redis. The command now is inside the shell file, it should be migrated to python.
