![](https://github.com/stratosphereips/AIVPN/blob/main/assets/Civilsphere-AI-VPN.png)

# Civilsphere AI VPN

The goal of this project is to better protect the privacy of civil society by researching and developing a locally and easy to implement VPN that checks the traffic of devices with AI-based detection to automatically block threats and stop dangerous privacy leaks. The detection of malicious threats, attacks, infections and private leaked data is implemented using novel free software AI technology.

The AI VPN is a modular service that automates the generation and revocation of VPN accounts, featuring the automatic capture of network traffic for each account, and the automatic network traffic analysis and reporting of incidents. The AI VPN follows a microservices design and runs using Docker Compose.

![](https://github.com/stratosphereips/AIVPN/blob/main/assets/Civilsphere-AI-VPN-HowItWorks-1.png)


# Get Started

The project documentation and installation guide can be found at [aivpn.readthedocs.io](https://aivpn.readthedocs.io/).

The AI VPN is under active development. The functionality of the AI VPN is provided by multiple modules:

|   Module      | Version | Status | Description                                    |
|   ------      | ------- | ------ | -----------                                    |
| mod_manager   |     0.2 | active | Coordinates the operation of the AI VPN        |
| mod_redis     |     0.2 | active | Data storage and messaging system for modules  |
| mod_comm_recv |     0.2 | active | Responsible of receiving new VPN requests      |
| mod_comm_send |     0.2 | active | Responsible of sending messages back to users  |
| mod_report    |     0.2 | active | Responsible for traffic analysis and reporting |
| mod_slips     |     0.1 | active | Threat detection                               |
| mod_openvpn   |     0.1 | active | Provides the VPN service using OpenVPN         |
| mod_wireguard |     0.1 | active | Provides the VPN service using WireGuard       |
| mod_novpn     |     0.1 | active | Provides the unencrypted tunel using OpenVPN   |
| mod_pihole    |     0.1 | active | Provides DNS real time blocking using Pi-Hooe  | 

# Acknowledgements

This project was funded through the NGI0 PET Fund, a fund established by NLnet with financial support from the European Commission's Next Generation Internet programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 825310.

This project was developed by the Stratosphere Laboratory, Artificial Intelligence Centre, Faculty of Electrical Engineering, Czech Technical University in Prague (2020-2021).

The AI VPN threat detection is provided by the [Stratosphere Linux IPS](https://github.com/stratosphereips/StratosphereLinuxIPS) developed at the Stratosphere Laboratory.

We would like to specially acknowledge the contributions of the following individuals:

* Veronica Valeros
* Sebastian Garcia
* Maria Rigaki
* Joaquin Bogado
* Alya Gomaa
