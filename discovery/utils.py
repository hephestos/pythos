# import python modules
import logging
import os

# import django modules
from django.utils import timezone
from django.db.models import Count
from django.db import IntegrityError

# import third party modules
from netaddr import IPNetwork
from scapy import sniff, Ether
from profilehooks import profile

# import project specific model classes
from .models import Interface, Net, Socket, Connection, DNScache
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
                    count_ips__gt=threshold,
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
        self.____contents = pkt.__bytes__()
        self.____time = pkt.time

    def __call__(self):
        """Get the original scapy packet."""
        pkt = Ether(self.____contents)
        pkt.time = self.____time
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

    # see whether we like the package or not
    if not (p.haslayer('Ether') and p.haslayer('IP')):
        return

    # Save the source interface
    try:
        src_interface = Interface.objects.get(
                            address_ether=p['Ether'].src,
                            address_inet=p['IP'].src,
                            origin=current_origin,
                            ttl_seen__in=[0, p['IP'].ttl],
                        )

        setattr(src_interface, 'tx_pkts', src_interface.tx_pkts + 1)
        setattr(src_interface, 'tx_bytes', src_interface.tx_bytes + p.len)

        src_interface.save()

    except Interface.DoesNotExist:
        src_interface = Interface.objects.create(address_ether=p['Ether'].src,
                                                 address_inet=p['IP'].src,
                                                 tx_pkts=1,
                                                 tx_bytes=p.len,
                                                 ttl_seen=p['IP'].ttl,
                                                 first_seen=timezone.now(),
                                                 origin=current_origin,
                                                 )
    except AttributeError:
        print('Raised AttributeError when reading source from package:')
        print(p.summary)
        return

    except IntegrityError:
        # Since we are not thread-safe,
        # we ignore attempts to create duplicate entries
        pass

    # Save the destination interface
    try:
        dst_interface = Interface.objects.get(
                            address_ether=p['Ether'].dst,
                            address_inet=p['IP'].dst,
                            origin=current_origin,
                        )

        setattr(dst_interface, 'rx_pkts', dst_interface.rx_pkts + 1)
        setattr(dst_interface, 'rx_bytes', dst_interface.rx_bytes + p.len)

        dst_interface.save()

    except Interface.DoesNotExist:
        dst_interface = Interface.objects.create(address_ether=p['Ether'].dst,
                                                 address_inet=p['IP'].dst,
                                                 rx_pkts=1,
                                                 rx_bytes=p.len,
                                                 first_seen=timezone.now(),
                                                 origin=current_origin,
                                                 )
    except AttributeError:
        print('Raised AttributeError when reading destination from package:')
        print(p.summary())
        return

    except IntegrityError:
        # Since we are not thread-safe,
        # we ignore attempts to create duplicate entries
        pass

    # Update the sockets
    try:
        if p['Ether'].type == 0x0800:
            # IPv4
            src_socket, new_src_socket = Socket.objects.get_or_create(
                                            interface=src_interface,
                                            port=p['IP'].sport,
                                            protocol_l4=p['IP'].proto
                                            )

            dst_socket, new_dst_socket = Socket.objects.get_or_create(
                                            interface=dst_interface,
                                            port=p['IP'].dport,
                                            protocol_l4=p['IP'].proto
                                                                      )

        elif p['Ether'].type == 0x86DD:
            # IPv6
            src_socket, new_src_socket = Socket.objects.get_or_create(
                                            interface=src_interface,
                                            port=p['IP'].sport,
                                            protocol_l4=p['IP'].nh
                                            )

            dst_socket, new_dst_socket = Socket.objects.get_or_create(
                                            interface=dst_interface,
                                            port=p['IP'].dport,
                                            protocol_l4=p['IP'].nh
                                            )
        else:
            # If we don't understand the protocol skip to the next package
            return

    except AttributeError:
        print('Raised AttributeError when reading ports from package:')
        print(p.summary())
        return

    except IntegrityError:
        # Since get_or_create is not thread-safe,
        # we ignore attempts to create duplicate entries
        pass

    # Find DNS records
    if p['IP'].sport == 53:
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

    # Find DHCP ACKs
    if p['IP'].sport == 67:
        try:
            # FIXME find names for numeric indices
            if p[4].options[0][1] == 5:
                # DHCP ACK
                ip_network = IPNetwork(p['IP'].dst)
                ip_network.prefixlen = sum([bin(int(x)).count('1') for x in
                                            p[4].options[5][1].split('.')]
                                           )

                gateway, new_gateway = \
                    Interface.objects.get_or_create(
                        address_inet=p[4].options[7][1],
                        net=Net.objects.all()[0]
                        )

                name_server, new_name_server = \
                    Interface.objects.get_or_create(
                        address_inet=p[4].options[8][1],
                        net=Net.objects.all()[0]
                        )

                updated_values_net = {'mask_inet': p[4].options[5][1],
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

    # Update the connections
    try:
        con = Connection.objects.get(src_socket=src_socket,
                                     dst_socket=dst_socket,
                                     protocol_l567=p.proto,
                                     )
        if p.proto == 6:
            # This is a TCP connection
            setattr(con, 'seq', p.seq)
            setattr(con, 'tx_pkts', con.tx_pkts + 1)
            setattr(con, 'tx_bytes', con.tx_bytes + p.len)

            con.save()

    except Connection.DoesNotExist:
        if p.proto == 6:
            con = Connection.objects.create(src_socket=src_socket,
                                            dst_socket=dst_socket,
                                            protocol_l567=p.proto,
                                            first_seen=timezone.now(),
                                            seq=p.seq,
                                            )
        else:
            con = Connection.objects.create(src_socket=src_socket,
                                            dst_socket=dst_socket,
                                            protocol_l567=p.proto,
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
