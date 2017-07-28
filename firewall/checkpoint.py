# import python modules
import logging
import os
import csv
from datetime import datetime
import xml.etree.ElementTree as ET
import ipaddress

# import django modules
from django.utils import timezone
from django.utils.timezone import make_aware, utc
from django.db.models import Count
from django.db import IntegrityError

# import third party modules
from profilehooks import profile

# import project specific model classes
from .models import Firewall, RuleSet, Rule, Log, Hit
from architecture.models import NetObject
from kb.models import ServiceName, OperatingSystem, Application
from discovery.models import Socket, Net, Interface
from architecture.models import NetObject, Service
from config.models import Site


def checkpoint_read_log_csv(filename):
    HEADERS = set(["Number", "Date", "Time", "Interface", "Origin", "Type",
                   "Action", "Service", "Source Port", "Source", "Destination",
                   "Protocol", "Rule", "Rule Name", "Current Rule Number",
                   "User", "Information", "Product", "Source Machine Name",
                   "Source User Name"])

    with open(filename, newline='') as csvfile:
        logreader = csv.DictReader(csvfile, delimiter=' ', quotechar='"')
        if logreader:
            log = Log.objects.create(
                    src_file=filename,
                  )

        if not HEADERS.issubset(set(logreader.fieldnames)):
            raise RuntimeError("The input file does not appear to be a \
                                CheckPoint log file. Quitting.")

        for row in logreader:
            if row['Type'] != 'Log':
                continue

            firewall, new_firewall = Firewall.objects.get_or_create(
                                        name=row['Origin']
                                     )

            ruleset, new_ruleset = RuleSet.objects.get_or_create(
                                        firewall=firewall,
                                        description='Derived from logs',
                                   )

            src, new_src = NetObject.objects.get_or_create(
                            name="HOST_" + row['Source'],
                           )
            src_interface, new_src_interface = Interface.objects.get_or_create(
                                                address_inet=row['Source']
                                               )
            src_interface.netobjects.add(src)
            src_interface.save()


            dst, new_dst = NetObject.objects.get_or_create(
                            name="HOST_" + row['Destination'],
                           )
            dst_interface, new_dst_interface = Interface.objects.get_or_create(
                                                address_inet=row['Destination']
                                               )
            dst_interface.netobjects.add(dst)
            dst_interface.save()


            src_service, new_src_service = ServiceName.objects.get_or_create(
                                                protocol_l3=row['Protocol'],
                                                port=row['Source Port'],
                                           )

            dst_service, new_dst_service = ServiceName.objects.get_or_create(
                                                protocol_l3=row['Protocol'],
                                                port=row['Service'],
                                           )

            rule, new_rule = Rule.objects.get_or_create(
                                ruleset=ruleset,
                                name=row['Rule Name'],
                                number=int('0'+row['Rule']),
                                action=row['Action'],
                             )

            rule.services.add(dst_service) 

            rule.srcs.add(src)

            rule.dsts.add(dst)

            hit = Hit.objects.create(
                    log=log,
                    rule=rule,
                    src=src,
                    src_service=src_service,
                    dst=dst,
                    dst_service=dst_service,
                    hit_time=make_aware(datetime.strptime(row['Date'] +
                                                          row['Time'], "%d%b%Y%H:%M:%S"), utc),
                    interface=row['Interface'],
                    user=row['User'],
                    src_machine_name=row['Source Machine Name'],
                    src_user_name=row['Source User Name'],
                  )


def checkpoint_create_network_objects_host(outfile="", prefix="", site_code="", type_long="", type_short="", change_request="", application=None):
    """Add Check Point NetworkGroup objects for an application, create Host objects and add them to the NetworkGroup

    Keyword arguments:
    outfile        -- output file
    prefix         -- first layer prefix for all objects
    site_code      -- location code used as second layer prefix
    type_long      -- long description for application, used in comments
    type_short     -- short description for application, used in object names
    change_request -- number of change request, used in comments
    application    -- the Application object of the application to be processed
    """

    if not application:
        raise RuntimeError("Application has to be specified. Quitting.")

    if outfile == "":
        raise RuntimeError("Outfile has to be specified. Quitting.")

    if type_long == "":
        raise RuntimeError("Long description has to be specified. Quitting.")
    
    if type_short == "":
        raise RuntimeError("Short description has to be specified. Quitting.")

    if prefix != "":
        prefix = prefix + "_"

    if site_code != "":
        site_code = site_code + "_"

    if change_request != "":
        change_request = " (CR " + change_request + ")"

    group_name = prefix + site_code + type_long + "s"

    f = open(outfile, "w", newline="\r\n")

    print("#################################################" + "#" * len(type_long), file=f)
    print("# Create NetworkGroup for all " + type_long + "-Objects globally #", file=f)
    print("#################################################" + "#" * len(type_long), file=f)
    print("#", file=f)
    print("create network_object_group " + group_name, file=f)
    print("modify network_objects " + group_name + " color 'blue'", file=f)
    print("modify network_objects " + group_name + " comments \"Group of all " + type_long + "s globally" + change_request + "\"", file=f)
    print("update network_objects " + group_name, file=f)
    print("#", file=f)
    print("#######################################################" + "#" * len(type_long) + "#" * len(group_name), file=f)
    print("# Create all " + type_long + "-Objects globally and add them to group " + group_name + " #", file=f)
    print("#######################################################" + "#" * len(type_long) + "#" * len(group_name), file=f)
    print("#", file=f)

    group_object, new_group_object = NetObject.objects.get_or_create(name=group_name)

    server_interfaces = list()
    for server_socket in application.servers.all():
        server_interfaces.append(server_socket.interface)
    server_interfaces = set(server_interfaces)

    for server_interface in server_interfaces:
        host_ip = server_interface.address_inet
        host_name = server_interface.system.name
        object_name = prefix + site_code + type_short + "_" + host_ip

        print("create host_plain " + object_name, file=f)
        print("modify network_objects " + object_name + " ipaddr " + host_ip, file=f)
        print("modify network_objects " + object_name + " color 'blue'", file=f)
        print("modify network_objects " + object_name + " comments \"" + host_name + " -> " + type_long + change_request + "\"", file=f)
        print("update network_objects " + object_name, file=f)
        print("addelement network_objects " + group_name + " '' network_objects:" + object_name, file=f)
        print("update network_objects " + group_name, file=f)
        print("#", file=f)

        host_object, new_host_object = NetObject.objects.get_or_create(name=object_name)
        group_object.children.add(host_object)
        group_object.save()
        server_interface.netobjects.add(host_object)

    print("####################################", file=f)
    print("# END -> Don't forget to update DB #", file=f)
    print("####################################", file=f)
    print("#", file=f)
    print("update_all", file=f)
    print("savedb", file=f)

    print(f)
    f.close()


def checkpoint_create_network_objects_network(outfile="", prefix="", unit_name="", change_request="", site_codes=list()):
    """Add Check Point NetworkGroup objects for networks, create individual network objects and add them to the NetworkGroup

    Keyword arguments:
    outfile        -- output file
    prefix         -- first layer prefix for all objects
    unit_name      -- name of the group to be created
    change_request -- number of change request, used in comments
    site_codes     -- A list of the code of the sites to be included in the group 
    """

    if not site_codes:
        raise RuntimeError("Site codes have to be specified. Quitting.")

    if outfile == "":
        raise RuntimeError("Outfile has to be specified. Quitting.")

    if unit_name == "":
        raise RuntimeError("Unit name has to be specified. Quitting.")
    
    if prefix != "":
        prefix = prefix + "_"

    if change_request != "":
        change_request = " (CR " + change_request + ")"

    group_name = prefix + unit_name + "_Site-Networks"

    f = open(outfile, "w", newline="\r\n")

    print("#########################################################" + "#" * len(unit_name), file=f)
    print("# Create NetworkGroup for all " + unit_name + "-Network-Objects globally #", file=f)
    print("#########################################################" + "#" * len(unit_name), file=f)
    print("#", file=f)
    print("create network_object_group " + group_name, file=f)
    print("modify network_objects " + group_name + " color 'green2'", file=f)
    print("modify network_objects " + group_name + " comments \"Group of all " + unit_name + " Site-Networks" + change_request + "\"", file=f)
    print("update network_objects " + group_name, file=f)
    print("#", file=f)
    print("############################################################" + "#" * len(unit_name) + "#" * len(group_name), file=f)
    print("# Create all " + unit_name + "-Site-Network globally and add them to group " + group_name + " #", file=f)
    print("############################################################" + "#" * len(unit_name) + "#" * len(group_name), file=f)
    print("#", file=f)

    group_object, new_group_object = NetObject.objects.get_or_create(name=group_name)

    for site_code in site_codes:
        site = Site.objects.get(code=site_code)

        nets = Net.objects.filter(site=site)

        for net in nets:
            object_name = prefix + site_code + "_NET_PC_" + net.address_inet + "_" + str(net.mask_cidr)

            print("create network " + object_name, file=f)
            print("modify network_objects " + object_name + " ipaddr " + net.address_inet, file=f)
            print("modify network_objects " + object_name + " netmask " + net.mask_inet, file=f)
            print("modify network_objects " + object_name + " color 'green2'", file=f)
            print("modify network_objects " + object_name + " comments \"" + site_code + " Site-Network" + change_request + "\"", file=f)
            print("update network_objects " + object_name, file=f)
            print("addelement network_objects " + group_name + " '' network_objects:" + object_name, file=f)
            print("update network_objects " + group_name, file=f)
            print("#", file=f)

            net_object, new_net_object = NetObject.objects.get_or_create(name=object_name)
            group_object.children.add(net_object)
            group_object.save()

    print("####################################", file=f)
    print("# END -> Don't forget to update DB #", file=f)
    print("####################################", file=f)
    print("#", file=f)
    print("update_all", file=f)
    print("savedb", file=f)
    
    print(f)
    f.close()


def checkpoint_export_network_object_subtree(outfile="", prefix="", network_type="", change_request="", parent_object=None):
    """Export a Check Point Object subtree starting from a given parent NetObject

    Keyword arguments:
    outfile        -- output file
    prefix         -- first layer prefix for all objects
    network_type    -- type of the objects to be created
    change_request -- number of change request, used in comments
    parent_object  -- The parent objects whose subtree is to be exported
    """

    if not parent_object:
        raise RuntimeError("Parent object has to be specified. Quitting.")

    if outfile == "":
        raise RuntimeError("Outfile has to be specified. Quitting.")

    if network_type == "":
        raise RuntimeError("Network type has to be specified. Quitting.")
    
    if prefix != "":
        prefix = prefix + "_"

    if change_request != "":
        change_request = " (CR " + change_request + ")"

    group_name = parent_object.name

    f = open(outfile, "w", newline="\r\n")

    print("#################################################" + "#" * len(group_name), file=f)
    print("# Create NetworkGroup for all " + group_name + "-Objects globally #", file=f)
    print("#################################################" + "#" * len(group_name), file=f)
    print("#", file=f)
    print("create network_object_group " + group_name, file=f)
    print("modify network_objects " + group_name + " color 'green2'", file=f)
    print("modify network_objects " + group_name + " comments \"Group of all " + group_name + "-Objects" + change_request + "\"", file=f)
    print("update network_objects " + group_name, file=f)
    print("#", file=f)
    print("#######################################################" + "#" * len(network_type) + "#" * len(group_name), file=f)
    print("# Create all " + network_type + "-Objects globally and add them to group " + group_name + " #", file=f)
    print("#######################################################" + "#" * len(network_type) + "#" * len(group_name), file=f)
    print("#", file=f)

    sub_objects = parent_object.children

    for sub_object in sub_objects.all():
        for sub_network in sub_object.networks.all():
            if sub_network.site:
                site_code = sub_network.site.code
            else:
                site_code = 'ZZZ'
            object_name = prefix + site_code + '_' +  network_type + '_' + sub_network.address_inet + "_" + str(sub_network.mask_cidr)

            print("create network " + object_name, file=f)
            print("modify network_objects " + object_name + " ipaddr " + sub_network.address_inet, file=f)
            print("modify network_objects " + object_name + " netmask " + sub_network.mask_inet, file=f)
            print("modify network_objects " + object_name + " color 'green2'", file=f)
            print("modify network_objects " + object_name + " comments \"" + site_code + " " + network_type + change_request + "\"", file=f)
            print("update network_objects " + object_name, file=f)
            print("addelement network_objects " + group_name + " '' network_objects:" + object_name, file=f)
            print("update network_objects " + group_name, file=f)
            print("#", file=f)

        for sub_interface in sub_object.interfaces.all():
            host_ip = sub_interface.address_inet
            host_name = sub_interface.system.name
            if sub_interface.system.site:
                site_code = sub_interface.system.site.code
            else:
                site_code = 'ZZZ'
            type_short = ''
            object_name = prefix + site_code + '_' + type_short + "_" + host_ip

            print("create host_plain " + object_name, file=f)
            print("modify network_objects " + object_name + " ipaddr " + host_ip, file=f)
            print("modify network_objects " + object_name + " color 'blue'", file=f)
            print("modify network_objects " + object_name + " comments \"" + host_name + change_request + "\"", file=f)
            print("update network_objects " + object_name, file=f)
            print("addelement network_objects " + group_name + " '' network_objects:" + object_name, file=f)
            print("update network_objects " + group_name, file=f)
            print("#", file=f)

    print("####################################", file=f)
    print("# END -> Don't forget to update DB #", file=f)
    print("####################################", file=f)
    print("#", file=f)
    print("update_all", file=f)
    print("savedb", file=f)

    print(f)
    f.close()


def checkpoint_import_xml_security_policy(filename):
    tree = ET.parse(filename)
    root = tree.getroot()

    rules = root.find('fw_policie').find('rule')

    if rules is None:
        raise RuntimeError("Could not import XML file " + filename)

    firewall = Firewall.objects.create(name="XML import from " + filename)
    ruleset = RuleSet.objects.create(firewall=firewall, description="XML import from " + filename)

    for r in rules:
        if r.find('Class_Name') is None:
            continue
        elif r.find('Class_Name').text != "security_rule":
            continue

        rule_name = r.find('name').text
        rule_uuid = r.find('Rule_UUID').text
        rule_number = int(r.find('Rule_Number').text)
        rule_action = r.find('action').find('action').find('Name').text
        rule_disabled = (r.find('disabled').text == "true")

        rule_sources = []
        for src in r.find('src').find('members').getchildren():
            if src.tag == "reference":
                rule_sources.append((src.find('Table').text, src.find('Name').text))

        rule_destinations = []
        for dst in r.find('dst').find('members').getchildren():
            if dst.tag == "reference":
                rule_destinations.append((dst.find('Table').text, dst.find('Name').text))

        rule_services = []
        for s in r.find('services').find('members').getchildren():
            if s.tag == "reference":
                rule_services.append((s.find('Table').text, s.find('Name').text))

        rule, new_rule = Rule.objects.get_or_create(ruleset=ruleset, uuid=rule_uuid)
        rule.name = rule_name
        rule.number = rule_number
        rule.action = rule_action
        rule.disabled = rule_disabled

        for table, name in rule_sources:
            if table == "network_objects":
                netobject, new_net_object = NetObject.objects.get_or_create(name=name)
                rule.srcs.add(netobject)

        for table, name in rule_destinations:
            if table == "network_objects":
                netobject, new_net_object = NetObject.objects.get_or_create(name=name)
                rule.dsts.add(netobject)

        for table, name in rule_services:
            if table == "services":
                service_object, new_service_object = Service.objects.get_or_create(name=name)
                rule.services.add(service_object)

        rule.save()


def checkpoint_import_xml_network_objects(filename, create_diffscript=False, outfile="", change_request=""):
    tree = ET.parse(filename)
    root = tree.getroot()

    objects = root.findall('network_object')

    if objects is None:
        raise RuntimeError("Could not import XML file " + filename)

    subobjects = []
    for o in objects:
        if o.find('Class_Name') is None:
            continue

        elif o.find('Class_Name').text == "network_object_group":
            object_name = o.find('Name').text

            for m in o.find('members').getchildren():
                if m.tag == "reference":
                    subobjects.append((object_name, m.find('Name').text))

            netobject, new_netobject = NetObject.objects.get_or_create(name=object_name)

        elif o.find('Class_Name').text == "host_plain":
            object_name = o.find('Name').text
            object_ipv4 = o.find('ipaddr').text
            object_ipv6 = o.find('ipaddr6').text

            if object_ipv4 != "":
                object_ip = object_ipv4
            elif object_ipv6 != "":
                object_ip = object_ipv6
            else:
                continue

            netobject, new_netobject = NetObject.objects.get_or_create(name=object_name)
            interface, new_interface = Interface.objects.get_or_create(address_inet=object_ip)

            interface.netobjects.add(netobject)
            interface.save()

        elif o.find('Class_Name').text == "network":
            object_name = o.find('Name').text
            object_ipv4 = o.find('ipaddr').text
            object_ipv6 = o.find('ipaddr6').text
            object_mask4 = o.find('netmask').text
            object_mask6 = o.find('netmask6').text

            if object_ipv4 != "":
                object_ip = object_ipv4
            elif object_ipv6 != "":
                object_ip = object_ipv6
            else:
                continue

            if object_mask4 != "":
                object_mask = object_mask4
            elif object_mask6 != "":
                object_mask = object_mask6
            else:
                continue

            object_cidr = ipaddress.ip_network(object_ip + '/' + object_mask, strict=False).prefixlen

            netobject, new_netobject = NetObject.objects.get_or_create(name=object_name)
            net, new_net = Net.objects.get_or_create(
                    address_inet=object_ip,
                    mask_inet=object_mask,
                    mask_cidr=object_cidr,
            )

            net.netobjects.add(netobject)
            net.save()

        else:
            object_name = o.find('Name').text
            netobject, new_netobject = NetObject.objects.get_or_create(name=object_name)
            if new_netobject:
                print("Found unknown Class '" + o.find('Class_Name').text + "'. Creating empty NetObject.")

    if create_diffscript:
        if change_request != "":
            change_request = " (CR " + change_request + ")"

        parents, children = zip(*subobjects)

        f = open(outfile, "w", newline="\r\n")

        for parent in set(parents):
            parent_object = NetObject.objects.get(name=parent)
            new_child_objects = parent_object.children.exclude(name__in=[child[1] for child in subobjects if child[0] == parent])

            for o in new_child_objects:
                for i in o.interfaces.all():
                    host_ip = i.address_inet
                    
                    if i.system is None:
                        continue

                    host_name = i.system.name
                    object_name = o.name

                    print("create host_plain " + object_name, file=f)
                    print("modify network_objects " + object_name + " ipaddr " + host_ip, file=f)
                    print("modify network_objects " + object_name + " color 'blue'", file=f)
                    print("modify network_objects " + object_name + " comments \"" + host_name + " -> " + parent + change_request + "\"", file=f)
                    print("update network_objects " + object_name, file=f)
                    print("addelement network_objects " + parent + " '' network_objects:" + object_name, file=f)
                    print("update network_objects " + parent, file=f)
                    print("#", file=f)

        f.close()

    for parent, child in subobjects:
        parent_object = NetObject.objects.get(name=parent)
        child_object = NetObject.objects.get(name=child)

        parent_object.children.add(child_object)
        parent_object.save()


def checkpoint_translate_port_descriptor(desc):
    if desc.find('>') == 0:
        port_min = int(desc.split('>')[-1]) + 1
        port_max = 65535

    elif desc.find('<') == 0:
        port_min = 0
        port_max = int(desc.split('<')[-1]) - 1

    elif desc.find('-') > 0 or desc.isdigit():
        ports = desc.split('-')
        port_min = int(ports[0])
        port_max = int(ports[-1])

    else:
        port_min = None
        port_max = None

    return (port_min, port_max)


def checkpoint_import_xml_services(filename):
    tree = ET.parse(filename)
    root = tree.getroot()

    services = root.findall('service')

    if services is None:
        raise RuntimeError("Could not import XML file " + filename)

    subobjects = []
    for s in services:
        if s.find('Class_Name') is None:
            continue

        elif s.find('Class_Name').text == "service_group":
            service_name = s.find('Name').text

            for m in s.find('members').getchildren():
                if m.tag == "reference":
                    subobjects.append((service_name, m.find('Name').text))
            
            service_object, new_service_object = Service.objects.get_or_create(name=service_name)

        elif s.find('Class_Name').text == "tcp_service":
            service_name = s.find('Name').text
            service_port_min, service_port_max = checkpoint_translate_port_descriptor(s.find('port').text)
            service_proto_l4 = 6
            service_description = s.find('comments').text
            service_category = s.find('Class_Name').text

            service_object, new_service_object = Service.objects.get_or_create(name=service_name)

            service_object.name = service_name
            service_object.proto_l4 = service_proto_l4
            service_object.port_min = service_port_min
            service_object.port_max = service_port_max
            service_object.description = service_description
            service_object.category = service_category

            service_object.save()

        elif s.find('Class_Name').text == "udp_service":
            service_name = s.find('Name').text
            service_port_min, service_port_max = checkpoint_translate_port_descriptor(s.find('port').text)
            service_proto_l4 = 17
            service_description = s.find('comments').text
            service_category = s.find('Class_Name').text

            service_object, new_service_object = Service.objects.get_or_create(name=service_name)

            service_object.name = service_name
            service_object.proto_l4 = service_proto_l4
            service_object.port_min = service_port_min
            service_object.port_max = service_port_max
            service_object.description = service_description
            service_object.category = service_category

            service_object.save()

        else:
            service_name = s.find('Name').text
            if s.find('protocol') is not None:
                if s.find('protocol').text != "":
                    service_proto_l4 = int(s.find('protocol').text)
                else:
                    service_proto_l4 = None
            else:
                service_proto_l4 = None

            service_description = s.find('comments').text
            service_category = s.find('Class_Name').text

            service_object, new_service_object = Service.objects.get_or_create(name=service_name)

            service_object.name = service_name
            service_object.proto_l4 = service_proto_l4
            service_object.description = service_description
            service_object.category = service_category

            service_object.save()

    for parent, child in subobjects:
        parent_object = Service.objects.get(name=parent)
        child_object = Service.objects.get(name=child)

        parent_object.children.add(child_object)
        parent_object.save()
