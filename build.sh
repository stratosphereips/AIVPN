#!/bin/bash

echo "Cleaning up"
docker rmi -f $(docker images -f "dangling=true" -q)
echo "" > logs/mod_openvpn.log
echo "" > logs/mod_comm_recv.log
echo "" > logs/mod_comm_send.log
echo "" > logs/mod_report.log
echo "" > logs/mod_manager.log

echo "Starting building modules"
cd mod_comm_recv
docker build -t aivpn_mod_comm_recv:latest .
cd ..

cd mod_comm_send
docker build -t aivpn_mod_comm_send:latest .
cd ..

cd mod_manager
docker build --no-cache -t aivpn_mod_manager:latest .
cd ..

cd mod_openvpn
docker build --no-cache -t aivpn_mod_openvpn:latest .
cd ..

cd mod_report
docker build -t aivpn_mod_report:latest .
cd ..

echo "Finished building modules"
