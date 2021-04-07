Installation
=============

This section explains how to install the components needed to run the AI VPN.
Once the code is downloaded, please refer to the next section: Configuration.

-----------------------------------
Installing Docker & Docker Compose
-----------------------------------

The AI VPN follows a micro-services design based on Docker and uses Docker
Compose to manage the multi-container application. The first step is therefore
to install Docker and Docker Compose in the host machine.

To install Docker we recommend following the installation steps instructed in:
https://docs.docker.com/engine/install/

To install Docker Compose we recommend following the installation steps as
instructed in: https://docs.docker.com/compose/install/

After the installation is successful, check the services are installed::

    $ sudo docker --version
    $ sudo docker-compose --version

The AI VPN was developed for:

    * Docker version 20.10.5
    * docker-compose version 1.25.0

-----------------------------------
Installing the AI VPN from Source
-----------------------------------

Download the source code of the AI VPN from GitHub::

    $ git clone https://github.com/stratosphereips/AIVPN.git
    $ cd AIVPN/

The AI VPN is a multi-container application. It currently has eight different
modules which are managed by Docker Compose using the docker-compose.yml file.
Each module plays a specific role in the application:

    * mod_redis: module that uses Redis as the core database for data storage.
    * mod_manager: module responsible for the core functionality of the AI VPN.
    * mod_openvpn: module provides the OpenVPN service.
    * mod_comm_recv: module capable of receiving VPN requests from users.
    * mod_comm_send: module responsible for sending data and files to users.
    * mod_traffic_capture: module to capture the network traffic of the users.
    * mod_slips: module that runs the Stratosphere IPS for threat detection.
    * mod_report: module responsible for reporting the threats found to users.

The next section will cover the configurations needed to run the AI VPN.
