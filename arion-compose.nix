{
  config.project.name = "aivpn";
  config.services = {
      mod_redis= {
        service.image = "redis";
        service.volumes = [ "${toString ./.}/data:/data/" ];
        service.restart = "on-failure";
      };
      mod_manager = {
        service.image = "civilsphere/aivpn_mod_manager";
        service.volumes = [ "${toString ./.}/data:/data/" "${toString ./.}/logs:/logs/" "${toString ./.}/config:/code/config:ro"  "${toString ./.}/common:/code/common"];
        service.depends_on = [ "mod_redis" ];
        service.restart = "on-failure";
      };
      mod_comm_recv = {
        service.image = "civilsphere/aivpn_mod_comm_recv:latest";
        service.volumes = [ "${toString ./.}/logs:/logs/" "${toString ./.}/config:/code/config:ro"  "${toString ./.}/common:/code/common"];
        service.depends_on = [ "mod_redis" "mod_manager" ];
        service.restart = "on-failure";
      };
      mod_comm_send = {
        service.image = "civilsphere/aivpn_mod_comm_send:latest";
        service.volumes = [ "${toString ./.}/data:/data/" "${toString ./.}/logs:/logs/" "${toString ./.}/config:/code/config:ro"  "${toString ./.}/common:/code/common"];
        service.depends_on = [ "mod_redis" "mod_manager" ];
        service.restart = "on-failure";
      };
      mod_report = {
        service.image = "civilsphere/aivpn_mod_report:latest";
        service.volumes = [ "${toString ./.}/data:/data/" "${toString ./.}/logs:/logs/" "${toString ./.}/config:/code/config:ro"  "${toString ./.}/common:/code/common"];
        service.depends_on = [ "mod_redis" "mod_manager" ];
        service.restart = "on-failure";
      };
      mod_slips = {
        service.image = "civilsphere/aivpn_mod_slips:latest";
        service.volumes = [ "${toString ./.}/data:/data/" "${toString ./.}/logs:/logs/" "${toString ./.}/config:/code/config:ro"  "${toString ./.}/common:/code/common"];
        service.depends_on = [ "mod_redis" "mod_manager" ];
        service.restart = "on-failure";
      };
      mod_openvpn = {
        service.image = "civilsphere/aivpn_mod_openvpn:latest";
        service.volumes = [  "${toString ./.}/data/conf_openvpn:/etc/openvpn" "${toString ./.}/data:/data/" "${toString ./.}/logs:/logs/" "${toString ./.}/config:/code/config:ro"  "${toString ./.}/common:/code/common"];
        service.ports = [ "1194:1194/tcp" ];
        service.depends_on = [ "mod_redis" "mod_manager" "mod_pihole" ];
        service.privileged = true;
        service.restart = "on-failure";
      };
      mod_wireguard = {
        service.image = "civilsphere/aivpn_mod_wireguard:latest";
        service.volumes = [  "${toString ./.}/data/conf_wireguard:/config" "${toString ./.}/data:/data/" "${toString ./.}/logs:/logs/" "${toString ./.}/config:/code/config:ro"  "${toString ./.}/common:/code/common"];
        service.ports = [ "1194:51820/udp" ];
        service.depends_on = [ "mod_redis" "mod_manager" "mod_pihole" ];
        service.restart = "on-failure";
        service.privileged = true;
        service.environment.PUID=1000;
        service.environment.PGID=1000;
        service.environment.TZ="Europe/Prague";
        service.environment.PEERS=1;
        service.environment.SERVERPORT=1194;
        service.environment.INTERNAL_SUBNET="192.168.254.0";
        service.environment.ALLOWEDIPS="0.0.0.0/0";
      };
      mod_novpn = {
        service.image = "civilsphere/aivpn_mod_novpn:latest";
        service.volumes = [  "${toString ./.}/data/conf_novpn:/etc/openvpn" "${toString ./.}/data:/data/" "${toString ./.}/logs:/logs/" "${toString ./.}/config:/code/config:ro"  "${toString ./.}/common:/code/common"];
        service.ports = [ "80:1194/tcp" ];
        service.depends_on = [ "mod_redis" "mod_manager" "mod_pihole" ];
        service.privileged = true;
        service.restart = "on-failure";
      };
      mod_pihole = {
        service.image = "pihole/pihole:latest";
        service.volumes = [ "${toString ./.}/data/conf_pihole:/etc/pihole" "${toString ./.}/data/conf_pihole/etc-dnsmasq.d/:/etc/dnsmasq.d/" "${toString ./.}/config:/code/config:ro"  "${toString ./.}/common:/code/common"];
        service.ports = [ "5900:80/tcp" ];
        service.environment.TZ="Europe/Prague";
        service.depends_on = [ "mod_redis" "mod_manager" ];
        service.restart = "on-failure";
      };
  };
}
