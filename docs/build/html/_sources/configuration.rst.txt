Configuration
=============

This section explains how to create the configuration file that the AI VPN
needs to run. Once the configuration is finished, please refer to the next
section: Deployment.

-----------------------------------
Creating the configuration file
-----------------------------------

The configuration file is used by all the modules. The current configuration
has five different sections:

    * REDIS: this section contains the address and channel names used by the
      modules to communicate with each other using a pub/sub scheme.
    * LOGS: this section contains the files and directories where each module
      will store their log files. Note: if the root directory (/logs) is
      changed, the docker-compose.yml file will also need to be updated to
      reflect that change.
    * IMAP: this section contains the credentials for the email address to be
      used to receive automated email VPN requests and send back the VPN
      profiles for users to connect. Note: we recommend to use a dedicated 
      email account and not your personal account to run this service.
    * STORAGE: this configuration specifies where the user data will be stored,
      including packet captures, network logs, and incident reports.
    * OPENVPN: this section gives the OpenVPN module the basic information
      needed to run the VPN service.
    * AIVPN: this section provides application level configurations, including
      when profiles expire, maximum profiles per account, etc.

Setting up the Configuration File
-----------------------------------

The AI VPN includes an example configuration file. Make a copy of the example
configuration into a new file in the same folder::

    $ cd AIVPN/
    $ cp config/config.ini.example config/config.ini

We recommend leaving all sections unchanged except for the IMAP and OPENVPN
sections which will be covered next.

Setting up the IMAP Configuration
-----------------------------------

The AI VPN generates VPN profiles automatically. Currently users can request
new VPN profiles via email by sending an email with an specific keyword: VPN.

The mod_comm_recv and mod_comm_send are the modules that uses the IMAP
configuration to receive VPN requests from the users and to send new VPN
profiles from the users.

We recommend using a dedicated email account to run this service. Some email
providers offer APP Passwords, which give non-official apps permissions to
access the email account. These passwords can be revoked at any time. 

The AI VPN was tested with GMail. Google provides instructions on how to set an
app password in an existing account: https://support.google.com/mail/answer/185833

Once the APP Password is generated, replace the values in the configuration
file with the appropriate values.

Setting up the OPENVPN Configuration
------------------------------------

The next step is to replace the example values of the OPEN VPN service with
the IP address or host of the host machine.

Find the public IPv4 address of the host machine::

    $ curl -4 icanhazip.com

Use this IP address to replace the placeholder in the configuration file::

    $ SERVER_PUBLIC_URL = udp://x.x.x.x
    $ PKI_ADDRESS = x.x.x.x

The next section will cover how to deploy the AI VPN using docker-compose.

Setting up the AIVPN Configuration
----------------------------------

The AIVPN follows certain restrictions regarding for how long the VPN profiles
remain active, how many active VPN profiles can a user have simultanously, and
others.

By default, the AIVPN will revoke issued VPN profiles every 72 hours. To extend
or reduce this time, replace the value of the following parameter (in hours)::

    $ EXPIRATION_THRESHOLD = X

The AIVPN allows a maximum of 5 simultanous active VPN profiles per user. To
increase or reduce this limit, replace the value of the following parameter::

    $ ACTIVE_ACCOUNT_LIMIT = X
