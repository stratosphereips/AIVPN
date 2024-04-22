![](https://github.com/stratosphereips/AIVPN/blob/main/assets/Civilsphere-AI-VPN.png)

# Civilsphere AI VPN

The goal of this project is to better protect the privacy of civil society by researching and developing a locally and easy to implement VPN that automatically verifies the traffic of devices with AI-based detection to automatically block threats and stop dangerous privacy leaks. The detection of malicious threats, attacks, infections and private leaked data is implemented using novel free software AI technology and automatic reporting.

The AI VPN is a modular service that automates the generation and revocation of VPN accounts, featuring the automatic capture of network traffic for each account, and the automatic network traffic analysis and reporting of incidents. The AI VPN follows a microservices design and runs using Docker Compose.

![](https://github.com/stratosphereips/AIVPN/blob/main/assets/Civilsphere-AI-VPN-HowItWorks-1.png)

# Features
The main features of AI VPN are:

- You can install it in your organization and give VPN accounts to your employees
- All the traffic going through the AI VPN is encrypted
- The traffic is automatically analyzed using Slips, a behavioral-based IDS using machine learning and rules
- You can use mails and Telegram channels to request a AI VPN profile. You can configure your own emails and Telegram channels
- A report is automatically created and sent to you using email or Telegram
- The backend VPN can be OpenSSL or Wireguard
- You can use unencrypted VPN in countries where encryption is forbidden, but still provide analysis
- It uses Pi-hole for automatic blocking of DNS requests and protection inside the VPN


# Get Started

The project documentation and installation guide can be found at [aivpn.readthedocs.io](https://aivpn.readthedocs.io/).

The AI VPN is under active development. The functionality of the AI VPN is provided by multiple modules:

|   Module      | Version | Status | Description                                    | DockerHub | 
|   ------      | ------- | ------ | -----------                                    |---- |
| mod_manager   |     0.2 | active | Coordinates the operation of the AI VPN        | ![Docker Pulls](https://img.shields.io/docker/pulls/civilsphere/aivpn_mod_manager?color=green)|
| mod_redis     |     0.2 | active | Data storage and messaging system for modules  | - |
| mod_comm_recv |     0.2 | active | Responsible of receiving new VPN requests      | ![Docker Pulls](https://img.shields.io/docker/pulls/civilsphere/aivpn_mod_comm_recv?color=green)|
| mod_comm_send |     0.2 | active | Responsible of sending messages back to users  | ![Docker Pulls](https://img.shields.io/docker/pulls/civilsphere/aivpn_mod_comm_send?color=green)|
| mod_report    |     0.2 | active | Responsible for traffic analysis and reporting | ![Docker Pulls](https://img.shields.io/docker/pulls/civilsphere/aivpn_mod_report?color=green)|
| mod_slips     |     0.1 | active | Threat detection                               | ![Docker Pulls](https://img.shields.io/docker/pulls/civilsphere/aivpn_mod_slips?color=green)|
| mod_openvpn   |     0.1 | active | Provides the VPN service using OpenVPN         | ![Docker Pulls](https://img.shields.io/docker/pulls/civilsphere/aivpn_mod_openvpn?color=green)|
| mod_wireguard |     0.1 | active | Provides the VPN service using WireGuard       | ![Docker Pulls](https://img.shields.io/docker/pulls/civilsphere/aivpn_mod_wireguard?color=green)|
| mod_novpn     |     0.1 | active | Provides the unencrypted tunel using OpenVPN   | ![Docker Pulls](https://img.shields.io/docker/pulls/civilsphere/aivpn_mod_novpn?color=green)|
| mod_pihole    |     0.1 | active | Provides DNS real time blocking using Pi-Hole  | - |

# Support

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/AI-VPN/).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)

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
