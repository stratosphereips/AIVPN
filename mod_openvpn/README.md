# To execute
docker build -t aivpn_mod_openvpn:latest
docker run -dit -v $(pwd)/certs:/certs aivpn_mod_openvpn /bin/bash /code/mod_comm_openvpn.sh
