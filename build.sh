#!/bin/bash

echo "Cleaning up"
echo "" > logs/mod_openvpn.log
echo "" > logs/mod_comm_recv.log
echo "" > logs/mod_comm_send.log
echo "" > logs/mod_report.log
echo "" > logs/mod_manager.log
echo "" > logs/mod_slips.log

echo "Starting building modules"
cd mod_comm_recv
docker build -t aivpn_mod_comm_recv:latest .
cd ..

cd mod_comm_send
docker build -t aivpn_mod_comm_send:latest .
cd ..

cd mod_manager
docker build -t aivpn_mod_manager:latest .
cd ..

cd mod_openvpn
docker build -t aivpn_mod_openvpn:latest .
cd ..

cd mod_report
docker build -t aivpn_mod_report:latest .
cd ..

cd mod_slips
docker build -t aivpn_mod_slips:latest .
cd ..

docker rmi -f $(docker images -f "dangling=true" -q)
echo "Finished building modules"
