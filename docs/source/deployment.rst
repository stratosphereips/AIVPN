Deployment
=============

This section explains how to build the AI VPN modules docker images and how to
deploy the AI VPN service using docker-compose.

Build the AI VPN Container Modules
----------------------------------

The AI VPN comes with a bash script that builds the images automatically. The
script `build.sh` contains three main sections:

    * Cleaning up the docker images.
    * Cleaning up the AI VPN log files.
    * Building the AI VPN container images using docker commands.

NOTE: The cleaning up of the docker images will remove all dangling docker images,
that is, docker images that have no links or relationships with images that are
tagged. Cleaning dangling images frees space. If you do not want to perform
this step, comment the following line from the `build.sh` script::

    $ docker rmi -f $(docker images -f "dangling=true" -q)

Run the build script to build the container images::

    $ cd AIVPN/
    $ sudo ./build.sh

Deploy the AI VPN service
-------------------------

The deployment of the AI VPN is done using docker-compose::

    $ cd AIVPN/
    $ mv docker-compose_EXAMPLE.yml docker-compose.yml
    $ sudo docker-compose -f docker-compose.yml up


Check the AI VPN Service Health
-------------------------------

Check the AI VPN modules are running using Docker::

    $ sudo docker ps

Check the AI VPN modules are working using the logs::

    $ cd AIVPN/
    $ tail -f logs/*.log

Check the AI VPN email configuratio works:

    * Send an email to the email address used for the service with the word:
      `VPN` in the body or subject of the email.
    * After a few minutes a new VPN profile should be received.
