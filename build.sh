#!/bin/bash

echo "Stopping the AI VPN service"
docker stack rm aivpn

echo "Cleaning up"
docker rmi aivpn_mod_comm_recv
docker rmi aivpn_mod_comm_send
docker rmi aivpn_mod_manager
docker rmi aivpn_mod_openvpn
docker rmi aivpn_mod_report
docker rmi aivpn_mod_traffic_capture
echo "" > logs/mod_openvpn.log
echo "" > logs/mod_comm_recv.log
echo "" > logs/mod_comm_send.log
echo "" > logs/mod_traffic_capture.log
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

cd mod_traffic_capture
docker build -t aivpn_mod_traffic_capture:latest .
cd ..

echo "Finished building modules"

echo "Deploying the services Stack"
docker stack deploy aivpn -c stack.yml
