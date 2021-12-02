AI VPN Using Nix Arion
======================

What is Nix?
------------

Nix is a packet manager that uses a model that allows reproducibility of packages and builds using declarative definitions. 
Learn more about Nix and NixOS at `NixOS Quick Start <https://nixos.org/manual/nix/stable/quick-start.html>`.

What is Arion?
--------------

Arion is a Nix tool designed to help launch modular docker based applications on Nix. Arion was designed with the same Nix principles in mind and follows a declarative approach. Arion focuses on providing an easier deployment and better performance. Learn more about Arion at `Arion Documentation <https://docs.hercules-ci.com/arion/>`.

How can the AI VPN deployed using Nix Arion?
--------------------------------------------

Once Nix package manager and Arion are already installed, you can start the service with a simple command::

    $ cd AIVPN/
    $ arion up -d

To stop the service run::

    $ arion down

If you need to change the configuration of the services, edit the file::

    * arion-compose.nix

Note: Arion has some limitations and may not support all the configuration parameters of docker-compose. This is why at the moment the Pi-Hole module is not supported through Arion. 
