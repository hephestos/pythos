# import python modules
import logging
import os

# import django modules
from django.utils import timezone
from django.db.models import Count, Q
from django.db import IntegrityError

# import third party modules
from netaddr import IPNetwork
from scapy.all import sniff, Ether
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from profilehooks import profile

# import project specific model classes
from .models import Interface, Net, Socket, Connection, DNScache
from .models import System
from kb.models import OperatingSystem


def guess_gateways_by_connections(threshold):
    gateways = Interface.objects.values(
                    'address_ether',
                ).annotate(
                    count_ips=Count('address_inet',
                                    distinct=True
                                    ),
                    count_src_cons=Count('sockets__src_connections',
                                         distinct=True
                                         ),
                    count_dst_cons=Count('sockets__dst_connections',
                                         distinct=True
                                         ),
                ).filter(
                    count_ips__gte=threshold,
                )

    return gateways


def guess_distances_by_ttl():
    for interface in Interface.objects.all():
        if interface.ttl_seen > 0:
            default_ttl = OperatingSystem.objects.filter(
                                default_ttl__gte=interface.ttl_seen,
                            ).order_by(
                                'default_ttl',
                            ).values(
                                'default_ttl',
                            ).first()['default_ttl']
            interface.distance = default_ttl - interface.ttl_seen
        else:
            interface.distance = -1
        interface.save()


def guess_networks_by_broadcasts():
    # get known networks
    known_netaddresses = []

    networks = Net.objects.order_by('address_inet',
                                    'origin__plant_flag',
                                    )

    for net in networks:
        if net.address_inet not in known_netaddresses:
            known_netaddresses.append(net.address_inet)

    # find broadcast addresses
    broadcasts = Interface.objects.values(
                        'address_ether',
                        'address_inet',
                    ).filter(
                        address_ether="FF:FF:FF:FF:FF:FF",
                        net__isnull=True,
                    ).order_by(
                        'address_inet',
                    ).distinct()

    for bcast in broadcasts:
        # find the IP addresses that have sent packets
        # to this broadcast address
        source = Interface.objects.filter(
                        address_inet=bcast['address_inet'],
                    ).exclude(
                        sockets__dst_connections__src_socket__interface__address_inet="0.0.0.0",
                    ).values_list(
                        'sockets__dst_connections__src_socket__interface__address_inet',
                    ).order_by(
                        'sockets__dst_connections__src_socket__interface__address_inet',
                    ).first()

        if source:
            OCTET_SEPARATOR = "."

            source_octets = source[0].split(OCTET_SEPARATOR)
            bcast_octets = bcast['address_inet'].split(OCTET_SEPARATOR)
            netmask_octets = ["0", "0", "0", "0"]
            netaddr_octets = ["0", "0", "0", "0"]

            # The part of the source IP address that matches the broadcast
            # address is assumed to be the network address.
            for i_octet in range(len(source_octets)):
                if source_octets[i_octet] == bcast_octets[i_octet]:
                    netmask_octets[i_octet] = "255"
                    netaddr_octets[i_octet] = source_octets[i_octet]
                else:
                    # now things become complicated...
                    # + source_octets holds the lowest known IP address
                    #   within the broadcast domain
                    # + We try to claim the largest available network

                    netmask_octets[i_octet] = \
                        str((256 - (2 ** (
                                int(bcast_octets[i_octet]) - 1).bit_length())
                             ) & 0xFF
                            )
                    netaddr_octets[i_octet] = str(int(source_octets[i_octet]) &
                                                  int(netmask_octets[i_octet])
                                                  )

                    new_netaddr = OCTET_SEPARATOR.join(netaddr_octets)
                    new_netmask = OCTET_SEPARATOR.join(netmask_octets)
                    new_bcast = OCTET_SEPARATOR.join(bcast_octets)

                    if new_netaddr not in known_netaddresses:
                        known_netaddresses.append(new_netaddr)

                        Net.objects.create(address_inet=new_netaddr,
                                           mask_inet=new_netmask,
                                           address_bcast=new_bcast,
                                           )
                    break


def identify_systems():
    BYTE_SEPARATOR = ":"
    LOW_MULTICAST = 1101088686080       # 01:00:5e:00:00:00
    HIGH_MULTICAST = 1101097074687      # 01:00:5e:7f:ff:ff

    # create a new system for each unassigned MAC
    unassigned_macs = Interface.objects.values(
                                'address_ether',
                            ).filter(
                                system__isnull=True,
                            ).distinct()

    for interface in unassigned_macs:
        ether_number = int(interface['address_ether'].replace(BYTE_SEPARATOR, ''), 16)

        if interface['address_ether'] == "FF:FF:FF:FF:FF:FF" or (
            LOW_MULTICAST <= ether_number <= HIGH_MULTICAST
        ):
            continue

        mac_group = Interface.objects.values(
                                'address_ether',
                                'system',
                            ).filter(
                                address_ether=interface['address_ether'],
                            )

        new_system = System.objects.create()
        mac_group.update(system=new_system)

    # TODO identify systems with adjacent mac addresses


def packet_chunk(chunk, current_origin, packets):
    logging.info("Worker process with PID " + str(os.getpid()) +
                 " has started."
                 )

    while not chunk.empty():
        next_packet = chunk.get_nowait()
        process_packet(next_packet(), current_origin)

    logging.info("Worker process with PID " + str(os.getpid()) +
                 " has finished."
                 )


class PicklablePacket:
    """A container for scapy packets that can be pickled (in contrast
    to scapy packets themselves).
    This works for python 3.5.1 and scapy 3.0.0 """
    def __init__(self, pkt):
        self.__contents = pkt.__bytes__()
        self.__time = pkt.time

    def __call__(self):
        """Get the original scapy packet."""
        pkt = Ether(self.__contents)
        pkt.time = self.__time
        return pkt


def add_packet(packets):
    def add_to_queue(pkt):
        pick_packet = PicklablePacket(pkt)
        packets.put(pick_packet)

    return add_to_queue


def run_capture(interface, duration, packets):
    sniff(iface=interface,
          timeout=float(duration),
          store=0,
          prn=add_packet(packets)
          )


def read_pcap(filepath, packets):
    sniff(offline=filepath,
          prn=add_packet(packets)
          )


@profile
def process_packet(p, current_origin):
    if not p.haslayer('Ether'):
        # TODO consider packets without Ethernet layer
        #      (e.g. traffic captured from within a tunnel)
        return

    src_interface, dst_interface = \
        packet_get_interfaces(p, current_origin)
    if src_interface and dst_interface:
        src_socket, dst_socket = \
            packet_get_sockets(p, src_interface, dst_interface)
        if src_socket and dst_socket:
            packet_find_connections(p, src_socket, dst_socket)
            if p.haslayer('IP'):
                packet_find_dns_records(p)
                packet_find_dhcp_acks(p)


def packet_get_interfaces(p, current_origin):
    try:
        if p.haslayer('IP'):
            src_interface = Interface.objects.get(
                                address_ether=p[Ether].src,
                                address_inet=p[IP].src,
                                origin=current_origin,
                                ttl_seen__in=[0, p[IP].ttl],
                            )
        else:
            src_interface = Interface.objects.get(
                                address_ether=p[Ether].src,
                                address_inet__isnull=True,
                                origin=current_origin,
                            )

        setattr(src_interface, 'tx_pkts', src_interface.tx_pkts + 1)
        setattr(src_interface, 'tx_bytes', src_interface.tx_bytes + p.len)

        src_interface.save()

    except Interface.DoesNotExist:
        if p.haslayer('IP'):
            src_interface = Interface.objects.create(
                                address_ether=p[Ether].src,
                                address_inet=p[IP].src,
                                tx_pkts=1,
                                tx_bytes=p.len,
                                ttl_seen=p[IP].ttl,
                                first_seen=timezone.now(),
                                origin=current_origin,
                            )
        else:
            src_interface = Interface.objects.create(
                                address_ether=p[Ether].src,
                                tx_pkts=1,
                                tx_bytes=p.len,
                                first_seen=timezone.now(),
                                origin=current_origin,
                            )

    except AttributeError:
        print('Raised AttributeError when reading source from package:')
        print(p.summary)
        return (False, False)

    except IntegrityError:
        # Since we are not thread-safe,
        # we ignore attempts to create duplicate entries
        pass

    # Save the destination interface
    try:
        if p.haslayer('IP'):
            dst_interface = Interface.objects.get(
                                address_ether=p[Ether].dst,
                                address_inet=p[IP].dst,
                                origin=current_origin,
                            )
        else:
            dst_interface = Interface.objects.get(
                                address_ether=p[Ether].dst,
                                origin=current_origin,
                            )

        setattr(dst_interface, 'rx_pkts', dst_interface.rx_pkts + 1)
        setattr(dst_interface, 'rx_bytes', dst_interface.rx_bytes + p.len)

        dst_interface.save()

    except Interface.DoesNotExist:
        if p.haslayer('IP'):
            dst_interface = Interface.objects.create(
                                address_ether=p[Ether].dst,
                                address_inet=p[IP].dst,
                                rx_pkts=1,
                                rx_bytes=p.len,
                                first_seen=timezone.now(),
                                origin=current_origin,
                            )
        else:
            dst_interface = Interface.objects.create(
                                address_ether=p[Ether].dst,
                                rx_pkts=1,
                                rx_bytes=p.len,
                                first_seen=timezone.now(),
                                origin=current_origin,
                            )

    except AttributeError:
        print('Raised AttributeError when reading destination from package:')
        print(p.summary())
        return (False, False)

    except IntegrityError:
        # Since we are not thread-safe,
        # we ignore attempts to create duplicate entries
        pass

    return (src_interface, dst_interface)


def packet_get_sockets(p, src_interface, dst_interface):
    # Update the sockets
    try:
        if p[Ether].type == 0x0800:
            # IPv4
            src_socket, new_src_socket = Socket.objects.get_or_create(
                                            interface=src_interface,
                                            port=p[IP].sport,
                                            protocol_l4=p[IP].proto
                                            )

            dst_socket, new_dst_socket = Socket.objects.get_or_create(
                                            interface=dst_interface,
                                            port=p[IP].dport,
                                            protocol_l4=p[IP].proto
                                            )

        elif p[Ether].type == 0x86DD:
            # IPv6
            src_socket, new_src_socket = Socket.objects.get_or_create(
                                            interface=src_interface,
                                            port=p[IPv6].sport,
                                            protocol_l4=p[IPv6].nh
                                            )

            dst_socket, new_dst_socket = Socket.objects.get_or_create(
                                            interface=dst_interface,
                                            port=p[IPv6].dport,
                                            protocol_l4=p[IPv6].nh
                                            )
        else:
            # If we don't understand the protocol skip to the next package
            return (False, False)

    except AttributeError:
        print('Raised AttributeError when reading ports from package:')
        print(p.summary())
        return (False, False)

    except IntegrityError:
        # Since get_or_create is not thread-safe,
        # we ignore attempts to create duplicate entries
        pass

    return (src_socket, dst_socket)


def packet_find_dhcp_acks(p):
    # Find DHCP ACKs
    if p.sport == 67:
        try:
            dhcp_opts = scapy_get_packet_options(p[DHCP].options)

            if dhcp_opts['message-type'] == 5:
                # DHCP ACK
                ip_network = IPNetwork(p[IP].dst)
                ip_network.prefixlen = sum([bin(int(x)).count('1') for x in
                                           dhcp_opts['subnet_mask'].split('.')]
                                           )

                gateway, new_gateway = \
                    Interface.objects.get_or_create(
                        address_inet=dhcp_opts['router'],
                        net=Net.objects.all()[0]
                        )

                name_server, new_name_server = \
                    Interface.objects.get_or_create(
                        address_inet=dhcp_opts['name_server'],
                        net=Net.objects.all()[0]
                        )

                updated_values_net = {'mask_inet': dhcp_opts['subnet_mask'],
                                      'address_bcast': p[4].options[6][1],
                                      'gateway': gateway,
                                      'name_server': name_server
                                      }

                our_net, new_net = Net.objects.update_or_create(
                                    address_inet=str(ip_network.network),
                                    defaults=updated_values_net,
                                    )
        except AttributeError:
            print('Raised AttributeError when reading DHCP ACK from package:')
            print(p.show())


def packet_find_connections(p, src_socket, dst_socket):
    # Update the connections
    try:
        if p[Ether].type == 0x0800:
            # IPv4
            proto = p.proto

        elif p[Ether].type == 0x86DD:
            # IPv6
            proto = p.nh

        con = Connection.objects.get(
                Q(src_socket=src_socket) | Q(src_socket=dst_socket),
                Q(dst_socket=dst_socket) | Q(dst_socket=src_socket),
                protocol_l567=proto,
                closed_flag=False,
                )

        setattr(con, 'tx_pkts', con.tx_pkts + 1)
        setattr(con, 'tx_bytes', con.tx_bytes + p.len)

        if p.haslayer('TCP'):
            setattr(con, 'seq', p.seq)
            if p[TCP].flags & 0x2:
                setattr(con, 'syn_flag', True)
            if p[TCP].flags & 0x5:
                setattr(con, 'closed_flag', True)

        con.save()

    except Connection.DoesNotExist:
        if proto == 6:
            if p[TCP].flags & 0x2:
                # SYN flag is set. The package was sent by the source of the
                # connection.
                con = Connection.objects.create(src_socket=src_socket,
                                                dst_socket=dst_socket,
                                                protocol_l567=proto,
                                                first_seen=timezone.now(),
                                                seq=p.seq,
                                                syn_flag=True,
                                                )
            else:
                # We missed the SYN packet. Source and destination infomation
                # is not reliable. We assume the higher port is the source.
                if p.sport >= p.dport:
                    con = Connection.objects.create(src_socket=src_socket,
                                                    dst_socket=dst_socket,
                                                    protocol_l567=proto,
                                                    first_seen=timezone.now(),
                                                    seq=p.seq,
                                                    )
                else:
                    con = Connection.objects.create(src_socket=dst_socket,
                                                    dst_socket=src_socket,
                                                    protocol_l567=proto,
                                                    first_seen=timezone.now(),
                                                    seq=p.seq,
                                                    )

        else:
            con = Connection.objects.create(src_socket=src_socket,
                                            dst_socket=dst_socket,
                                            protocol_l567=proto,
                                            first_seen=timezone.now(),
                                            )

    except IntegrityError:
        # Since we are not thread-safe,
        # we ignore attempts to create duplicate entries
        pass

    except Connection.MultipleObjectsReturned:
        # This shouldn't happen, but in case it does we will
        # skip to the next package
        return


def packet_find_dns_records(p):
    # Find DNS records
    if p.sport == 53:
        try:
            updated_values_dnscache = {"name": p[6].rrname,
                                       "last_seen": timezone.now()
                                       }

            DNScache.objects.update_or_create(address_inet=p[6].rdata,
                                              defaults=updated_values_dnscache
                                              )
        except AttributeError:
            print('Raised AttributeError when reading DNS answer '
                  'from package:')
            print(p.summary())

        except TypeError:
            print('Raised TypeError when reading DNS answer from package:')
            print(p.summary())

        except IndexError:
            # This was not a DNSRR. Disregard.
            pass


def scapy_get_packet_options(options):
    if not type(options) is list:
        return False
    optdict = {}
    for optlist in options:
        if type(optlist) is tuple and len(optlist) > 1:
            optdict[optlist[0]] = list(set(optlist[1:]))[0]
    return optdict
