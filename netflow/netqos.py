# import python modules
import logging
import os
import csv
import sys
from datetime import datetime

# import django modules
from django.utils import timezone
from django.utils.timezone import make_aware, utc
from django.db.models import Count
from django.db import IntegrityError, DataError
from django.core.exceptions import MultipleObjectsReturned

# import third party modules
from profilehooks import profile

# import project specific model classes
from .models import Log, Flow 
from discovery.models import Interface, Socket
from architecture.models import Service


def netqos_read_netflow_csv(filename):
    HEADERS = set(["Protocol", "SourceAddress", "SourcePort", "DestinationAddress", "DestinationPort", "BytesInVolume", "BytesInPercentOfTotalTraffic", "FlowCount", "PacketsInVolume", "PacketsInPercentOfTotalTraffic"])

    with open(filename, newline='') as csvfile:
        logreader = csv.DictReader(csvfile, delimiter=',')
        
        if not HEADERS.issubset(set(logreader.fieldnames)):
            print(HEADERS.difference(set(logreader.fieldnames)))
            raise RuntimeError("The input file does not appear to be a \
                                NetQoS netflow file. Quitting.")

        if logreader:
            log = Log.objects.create(
                    src_file=filename,
                  )
        else:
            return

        for row in logreader:
#            try:
                src_iface, new_src_iface = Interface.objects.get_or_create(
                                            address_inet=row['SourceAddress'],
                                           )

                src_socket, new_src_socket = Socket.objects.get_or_create(
                                                interface=src_iface,
                                                port=row['SourcePort'],
                                                protocol_l4=row['Protocol'],
                                             )

                if src_socket.services.count() == 0:
                    services = Service.objects.filter(
                                proto_l4=src_socket.protocol_l4,
                                port_min__lte=src_socket.port,
                                port_max__gte=src_socket.port,
                               )
                    services = list(services)
                    src_socket.services.add(*services)
                    src_socket.save()

                dst_iface, new_dst_iface = Interface.objects.get_or_create(
                                            address_inet=row['DestinationAddress'],
                                           )

                dst_socket, new_dst_socket = Socket.objects.get_or_create(
                                                interface=dst_iface,
                                                port=row['DestinationPort'],
                                                protocol_l4=row['Protocol'],
                                             )

                if dst_socket.services.count() == 0:
                    services = Service.objects.filter(
                                proto_l4=dst_socket.protocol_l4,
                                port_min__lte=dst_socket.port,
                                port_max__gte=dst_socket.port,
                               )
                    services = list(services)
                    dst_socket.services.add(*services)
                    dst_socket.save()

                flow, new_flow = Flow.objects.get_or_create(
                                    log=log,
                                    src=src_socket,
                                    dst=dst_socket,
                                )

                flow.bytes_in_volume = row['BytesInVolume']
#                flow.bytes_in_rate = row['BytesInRate']
                flow.bytes_in_percent = row['BytesInPercentOfTotalTraffic']
                flow.flow_count = row['FlowCount']
                flow.packets_in_volume = row['PacketsInVolume']
#                flow.packets_in_rate = row['PacketsInRate']
                flow.packets_in_percent = row['PacketsInPercentOfTotalTraffic']
            
                flow.save()

#            except:
#                print(sys.exc_info()[0])
#                continue

        log.import_complete = True
        log.save()
