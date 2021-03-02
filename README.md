# Civilsphere AIVPN

To better protect the privacy of civil society by researching and developing a locally and easy to implement VPN that checks the traffic of devices with AI-based detection to automatically block threats and stop dangerous privacy leaks. The detection of malicious threats, attacks, infections and private leaked data is implemented using novel free software AI technology.

## Get started

Build the images:
```bash
cd mod_report
docker build -t aivpn_mod_report:latest .
```

Deploy the service:
```bash
$ docker stack deploy aivpn -c stack.yml
```

Check the status of the deployment:
```bash
docker stack ps
docker service ls
docker container ps
```
