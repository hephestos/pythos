import os
import csv
import socket
import ldap3
from profilehooks import profile
from django.db.models import Q, Count
from urllib.parse import urlsplit
from kb.models import Application, OperatingSystem
from discovery.models import Socket as discovery_Socket
from discovery.models import System, Interface


def query_ad_for_hostname(hostname, ldap_connection):
    """
    Query the Active Directory for a given hostname.

    Parameters:
    - hostname (string): FQDN to be used in the query.
    - ldap_connection (ldap3.connection): Connection to an LDAP server to be used for the query.
    """

    DOMAINS =  [ '' ]

    fqdn = hostname.split('.')
    computer_name = fqdn[0]
    search_base = ','.join(['dc=' + s for s in fqdn[1:]])
    search_filter = '(&(objectClass=computer)(name=' + computer_name + '))'
    if ldap_connection.bound:
        try:
            search = ldap_connection.search(search_base=search_base, search_filter=search_filter, attributes=ldap3.ALL_ATTRIBUTES)
            return ldap_connection.entries
        except:
            print('Could not get AD information for hostname ' + hostname)
            return []


def set_unknown_names_by_ip():
    floating_interfaces = Interface.objects.filter(system__isnull=True, is_private=True)

    for i in floating_interfaces:
        try:
            hostname = socket.gethostbyaddr(i.address_inet)[0]
        except:
            print('Could not resolve hostname for IP ' + i.address_inet + '. Skipping entry.')
            continue
        
        system, new_system = System.objects.get_or_create(name=hostname)
        i.system = system
        i.save()

        system.save()


@profile
def set_host_description_ad_information():
    systems = System.objects.filter(description__exact='').exclude(name__exact='').order_by('?')

    server = ldap3.Server(host='', get_info=ldap3.ALL)
    conn = ldap3.Connection(server=server, user='', password='', authentication=ldap3.NTLM, read_only=True)

    try:
        conn.bind()
    except:
        print('Cannot establish a session with the LDAP server. Quitting.')
        raise

    for s in systems:
        hostname = s.name
        
        try:
            ad_info = query_ad_for_hostname(hostname, conn)
        except:
            print('Error accessing the AD. Maybe the connection has timed out or the session has expired. Quitting.')
            conn.unbind()
            raise

        try:
            os = ad_info[0].operatingSystem
        except:
            os = ''

        try:
            dn = ad_info[0].distinguishedName
        except:
            dn = ''

        if os != '':
            operating_system, new_operating_system = OperatingSystem.objects.get_or_create(vendor='Microsoft', product=os)
            s.os = operating_system

        if dn != '':
            s.description = dn

        s.save()

    conn.unbind()


def set_network_by_interface(Interface):
    if Interface.net is not None:
        return -1


def find_duplicate_model_fields_by_model(model, field):
    return model.objects.values(field).annotate(Count('pk')).filter(pk__count__gt=1)


def get_sockets_for_rule(rule, src_sockets=set(), dst_sockets=set()):
    for service in rule.services.all():
        ports = get_portrange_and_proto_for_service(service)

        for port in ports:
            for src in rule.srcs.all():
                src_sockets.add(get_sockets_for_netobject(src, proto_l4=port[2]))

            for dst in rule.dsts.all():
                dst_sockets.add(get_sockets_for_netobject(dst, port_min=port[0], port_max=port[1], proto_l4=port[2]))

    return src_sockets, dst_sockets


def get_portrange_and_proto_for_service(o, ports=list()):
    if o.proto_l4 and o.port_min and o.port_max:
        ports.append([o.port_min, o.port_max, o.proto_l4])

    for c in o.children.all():
        get_portrange_and_proto_for_service(c)

    return ports
    

def get_sockets_for_netobject(o, port_min=0, port_max=65535, proto_l4=0, sockets=set()):
    for n in o.networks.all():
        for i in n.interface_set.all():
            for s in i.sockets.filter(port__gte=port_min, port__lte=port_max, protocol_l4=proto_l4):
                sockets.add(s.pk)

    for i in o.interfaces.all():
        for s in i.sockets.filter(port__gte=port_min, port__lte=port_max, protocol_l4=proto_l4):
            sockets.add(s.pk)

    for c in o.children.all():
        get_sockets_for_netobject(c)

    return sockets
