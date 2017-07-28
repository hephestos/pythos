import ipaddress

from django.db.models import Q

from .models import Flow

# ip_example = 172.29.201.x

def run_query(network1, network2):
    netmask1 = int(network1.split('/')[1])
    netmask2 = int(network2.split('/')[1])

    octets1 = network1.split('.')
    octets2 = network2.split('.')

    if netmask1 >= 24:
        netaddr1 = octets1[0] + "." + octets1[1] + "." + octets1[2]
    elif netmask1 >= 16:
        netaddr1 = octets1[0] + "." + octets1[1]
    elif netmask1 >= 8:
        netaddr1 = octets1[0]
    else:
        netaddr1 = ""

    if netmask2 >= 24:
        netaddr2 = octets2[0] + "." + octets2[1] + "." + octets2[2]
    elif netmask2 >= 16:
        netaddr2 = octets2[0] + "." + octets2[1]
    elif netmask2 >= 8:
        netaddr2 = octets2[0]
    else:
        netaddr2 = ""

    flows = Flow.objects.filter(Q(src__name__startswith=netaddr1) | Q(dst__name__startswith=netaddr1) | Q(src__name__startswith=netaddr2) | Q(dst__name__startswith=netaddr2))
    print("Query: " + str(flows.query))
    print("Selected " + str(flows.count()) + " out of " + str(Flow.objects.all().count()) + " objects.")
    for item in flows:
        if ((ipaddress.ip_address(item.src.name) in ipaddress.ip_network(network1)) and \
           (ipaddress.ip_address(item.dst.name) in ipaddress.ip_network(network2))) or \
           ((ipaddress.ip_address(item.src.name) in ipaddress.ip_network(network2)) and \
           (ipaddress.ip_address(item.dst.name) in ipaddress.ip_network(network1))):
            print(item.src.name + " -[" + item.dst_service.port + "/" + item.dst_service.protocol_l3 + "]-> " + item.dst.name)
