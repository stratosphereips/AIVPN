#!/bin/bash

echo "Cleaning up"
echo "" > logs/mod_openvpn.log
echo "" > logs/mod_novpn.log
echo "" > logs/mod_comm.log
echo "" > logs/mod_report.log
echo "" > logs/mod_manager.log
echo "" > logs/mod_slips.log
echo "" > logs/mod_wireguard.log

echo "Starting building modules"
cd mod_comm
docker build -t aivpn_mod_comm:latest .
cd ..

cd mod_manager
docker build -t aivpn_mod_manager:latest .
cd ..

cd mod_openvpn
docker build -t aivpn_mod_openvpn:latest .
cd ..

cd mod_novpn
docker build -t aivpn_mod_novpn:latest .
cd ..

cd mod_wireguard
docker build -t aivpn_mod_wireguard:latest .
cd ..

cd mod_report
docker build -t aivpn_mod_report:latest .
cd ..

cd mod_slips
docker build -t aivpn_mod_slips:latest .
cd ..

docker rmi -f $(docker images -f "dangling=true" -q)
echo "Finished building modules"
