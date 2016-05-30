import time
from scapy.all import *

from django.utils import timezone
from netaddr import IPNetwork
from django.db import IntegrityError
from django.db import connection as db_connection
from django.db.models import Sum, Min, Max, Count
from profilehooks import profile

from .models import System, Interface, Net, Socket, Connection, DNScache
from config.models import Origin
from kb.models import OperatingSystem

import logging
import multiprocessing

import cProfile

class PicklablePacket:
    """A container for scapy packets that can be pickled (in contrast
    to scapy packets themselves).
    This works for python 3.5.1 and scapy 3.0.0 """
    def __init__(self, pkt):
        self.__contents = pkt.__bytes__()
        self.__time = pkt.time

    def __call__(self):
        """Get the original scapy packet."""
        pkt = scapy.all.Ether(self.__contents)
        pkt.time = self.__time
        return pkt

def add_packet(packets):
        def add_to_queue(pkt):
            pick_packet = PicklablePacket(pkt)
            packets.put(pick_packet)

        return add_to_queue

def run_capture(interface, duration, packets):
        sniff(iface=interface, timeout=float(duration), store=0, prn=add_packet(packets))

def read_pcap(filepath, packets):
#        sniff(offline=filepath,count=100000, prn=add_packet(packets))
        sniff(offline=filepath, prn=add_packet(packets))

def DiscoveryTask(origin_uuid="",
                  offline=False,
                  interface="",
                  duration=0,
                  filepath="",
                  origin_description=""):

        # Get an instance of a logger
        logging.basicConfig(filename="/tmp/pythos_debug.log",level=logging.DEBUG)

        m = multiprocessing.Manager()
        packets = m.Queue()

        multiprocessing.log_to_stderr(logging.INFO)

        num_processes = os.cpu_count()
        if not num_processes: num_processes = 2
        
        pool = multiprocessing.Pool(processes = num_processes)

        if offline: 
            current_origin = Origin.objects.create( name="PCAP " + filepath,
                                                    description=origin_description,
                                                    sensor_flag=True,
                                                    plant_flag=False )

            discovery_process = pool.apply_async(read_pcap, args=(filepath, packets))
            logging.info("Starting to read pcap file: " + filepath)

        else:
            try:
                current_origin = Origin.objects.get ( uuid=origin_uuid )
            except:
                logging.error("Could not find specified origin: " + origin_uuid + " Aborting.")
                return

            discovery_process = pool.apply_async(run_capture, args=(interface, duration, packets))
            logging.info("Starting live capture on: " + interface)
        
        # For testing delete everything from previous captures
        # Interface.objects.all().delete()
        
        logging.info("Starting " + str(num_processes) + " worker processes.")

        time.sleep(5)
 
        while not discovery_process.ready() or not packets.empty():
            num_packets = packets.qsize()
            chunk_size = max(num_packets//num_processes, 100000)

            if num_packets > chunk_size:
                chunk = m.Queue()
                for i in range(chunk_size):
                    chunk.put(packets.get())
                logging.debug("Processing chunk with size: " + str(chunk_size))
                logging.debug(str(num_packets) + " packets in queue.")
                pool.apply_async(packet_chunk, args=(chunk,current_origin,packets))

            elif discovery_process.ready():
                logging.debug("Processing last chunk.")
                logging.debug(str(num_packets) + " packets in queue.")
                pool.apply(packet_chunk, args=(packets,current_origin,packets))

            time.sleep(1)

        pool.close()
        pool.join()

        if offline:
            logging.info("Pcap " + filepath + " has been processed successfully.")
        else:
            logging.info("Live capture on " + interface + " has been completed.")

def find_gateways_task(threshold):
    gateways = Interface.objects.values(
                    'address_ether',
                ).annotate(
                    count_ips      = Count('address_inet', distinct = True),
                    count_src_cons = Count('sockets__src_connections', distinct = True),
                    count_dst_cons = Count('sockets__dst_connections', distinct = True),
                ).filter(
                    count_ips__gt = threshold,
                )

def set_distances_task():
    for interface in Interface.objects.all():
        if interface.ttl_seen > 0:
            default_ttl = OperatingSystem.objects.filter(
                                default_ttl__gte = interface.ttl_seen
                            ).order_by(
                                'default_ttl'
                            ).values(
                                'default_ttl'
                            ).first()['default_ttl']
            interface.distance = default_ttl - interface.ttl_seen
        else:
            interface.distance = -1
        interface.save()

@profile
def process_packet(p,current_origin):

        # see whether we like the package or not
        if not (p.haslayer(Ether) and p.haslayer(IP)):
                return

        # Save the source interface
        try:
            src_interface = Interface.objects.get(
                                address_ether=p[Ether].src,
                                address_inet=p[IP].src,
                                origin=current_origin,
                                ttl_seen__in=[0, p[IP].ttl],
                            )

            setattr(src_interface, 'tx_pkts', src_interface.tx_pkts + 1)
            setattr(src_interface, 'tx_bytes', src_interface.tx_bytes + p.len)

            src_interface.save()

        except Interface.DoesNotExist:
                src_interface = Interface.objects.create( address_ether=p[Ether].src,
                                                          address_inet=p[IP].src,
                                                          tx_pkts=1,
                                                          tx_bytes=p.len,
                                                          ttl_seen=p[IP].ttl,
                                                          first_seen=timezone.now(),
                                                          last_seen=timezone.now(),
                                                          origin=current_origin )
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
                                address_ether=p[Ether].dst,
                                address_inet=p[IP].dst,
                                origin=current_origin,
                            )

            setattr(dst_interface, 'rx_pkts', dst_interface.rx_pkts + 1)
            setattr(dst_interface, 'rx_bytes', dst_interface.rx_bytes + p.len)

            dst_interface.save()

        except Interface.DoesNotExist:
                dst_interface = Interface.objects.create( address_ether=p[Ether].dst,
                                                          address_inet=p[IP].dst,
                                                          rx_pkts=1,
                                                          rx_bytes=p.len,
                                                          first_seen=timezone.now(),
                                                          last_seen=timezone.now(),
                                                          origin=current_origin )
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
                if p[Ether].type == 0x0800: # IPv4
                        src_socket, new_src_socket = Socket.objects.get_or_create( interface=src_interface,
                                                                                     port=p[IP].sport,
                                                                                     protocol_l4=p[IP].proto )

                        dst_socket, new_dst_socket = Socket.objects.get_or_create( interface=dst_interface,
                                                                                     port=p[IP].dport,
                                                                                     protocol_l4=p[IP].proto )

                elif p[Ether].type == 0x86DD: # IPv6
                        src_socket, new_src_socket = Socket.objects.get_or_create( interface=src_interface,
                                                                                     port=p[IP].sport,
                                                                                     protocol_l4=p[IP].nh )

                        dst_socket, new_dst_socket = Socket.objects.get_or_create( interface=dst_interface,
                                                                                     port=p[IP].dport,
                                                                                     protocol_l4=p[IP].nh )

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
        if p[2].sport == 53:
                try:
                        updated_values_dnscache = { "name" : p[6].rrname,
                                                    "last_seen" : timezone.now() }

                        DNScache.objects.update_or_create( address_inet=p[6].rdata,
                                                           defaults=updated_values_dnscache )
                except AttributeError:
                        print('Raised AttributeError when reading DNS answer from package:')
                        print(p.summary())

                except TypeError:
                        print('Raised TypeError when reading DNS answer from package:')
                        print(p.summary())

                except IndexError:
                        # This was not a DNSRR. Disregard.
                        pass

        # Find DHCP ACKs
        if p[2].sport == 67:
                try:
                        if p[4].options[0][1] == 5: # DHCP ACK
                                ip_network = IPNetwork(p[1].dst)
                                ip_network.prefixlen=sum(
                                        [bin(int(x)).count('1') for x in p[4].options[5][1].split('.')] )

                                gateway, new_gateway = Interface.objects.get_or_create(
                                                                address_inet=p[4].options[7][1],
                                                                net=Net.objects.all()[0] )

                                name_server, new_name_server = Interface.objects.get_or_create(
                                                                address_inet=p[4].options[8][1],
                                                                net=Net.objects.all()[0] )

                                updated_values_net = { 'mask_inet' : p[4].options[5][1],
                                                       'address_bcast' : p[4].options[6][1],
                                                       'gateway' : gateway,
                                                       'name_server' : name_server }
                               
                                our_net, new_net = Net.objects.update_or_create(
                                                        address_inet=str(ip_network.network),
                                                        defaults=updated_values_net )
                except AttributeError:
                        print('Raised AttributeError when reading DHCP ACK from package:')
                        print(p.show())

        # Update the connections
        try:
                con = Connection.objects.get( src_socket=src_socket,
                                              dst_socket=dst_socket,
                                              protocol_l567=p.proto )

                if p.proto == 6: # Check if this is a TCP connection 
                        setattr(con, 'seq', p.seq)

                setattr(con, 'tx_pkts', con.tx_pkts + 1)
                setattr(con, 'tx_bytes', con.tx_bytes + p.len)

                con.save()
                new_con = False

        except Connection.DoesNotExist:
                if p.proto==6:
                        con = Connection.objects.create( src_socket=src_socket,
                                                         dst_socket=dst_socket,
                                                         protocol_l567=p.proto,
                                                         first_seen=timezone.now(),
                                                         seq=p.seq )
                else:
                        con = Connection.objects.create( src_socket=src_socket,
                                                 dst_socket=dst_socket,
                                                 protocol_l567=p.proto,
                                                 first_seen=timezone.now() )

                new_con = True

        except IntegrityError:
                # Since we are not thread-safe,
                # we ignore attempts to create duplicate entries
                pass

        except Connection.MultipleObjectsReturned:
                # This shouldn't happen, but in case it does we will skip to the next package
                return

def packet_chunk(chunk, current_origin, packets):
        logging.info("Worker process with PID " + str(os.getpid()) + " has started.")
       
        while not chunk.empty():
            next_packet = chunk.get_nowait()
            process_packet(next_packet(), current_origin)
       
        logging.info("Worker process with PID " + str(os.getpid()) + " has finished.")
