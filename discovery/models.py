from django.db import models
from macaddress.fields import MACAddressField


class Net(models.Model):
    origin = models.ForeignKey('config.Origin', null=True, blank=True)
    site = models.ForeignKey('config.Site', null=True, blank=True)
    address_inet = models.GenericIPAddressField(db_index=True, null=True, blank=True)
    mask_inet = models.GenericIPAddressField(db_index=True, null=True, blank=True)
    address_bcast = models.GenericIPAddressField(db_index=True, null=True, blank=True)
    gateway = models.ForeignKey('System', null=True, related_name='+')
    name_server = models.ForeignKey('System', null=True, related_name='+')


class System(models.Model):
    site = models.ForeignKey('config.Site', null=True, blank=True)
    name = models.CharField(max_length=127)
    description = models.TextField()
    os = models.ForeignKey('kb.OperatingSystem', null=True, blank=True)


class Packet(models.Model):
    origin = models.ForeignKey('config.Origin', null=True, blank=True)
    pkt_bytes = models.BinaryField(null=True)
    pkt_time = models.DateTimeField(auto_now=False, null=True)
    first_layer = models.CharField(max_length=127, null=True, blank=True)
    payload_hash = models.BigIntegerField(null=True)
    processed_flag = models.BooleanField(default=False)
    failed_flag = models.BooleanField(default=False)


# Interface as an interface belonging to an identified system.
# NOT the interface used for capturing traffic!
class Interface(models.Model):
    origin = models.ForeignKey('config.Origin', null=True, blank=True)
    system = models.ForeignKey('System', null=True, blank=True)
    net = models.ForeignKey('Net', null=True, blank=True)
    address_ether = MACAddressField(integer=False, null=True, blank=True)
    address_inet = models.GenericIPAddressField(null=True, blank=True)
    distance = models.IntegerField(default=-1)
    tx_pkts = models.BigIntegerField(default=0)
    tx_bytes = models.BigIntegerField(default=0)
    rx_pkts = models.BigIntegerField(default=0)
    rx_bytes = models.BigIntegerField(default=0)
    ttl_seen = models.IntegerField(default=0)
    first_seen = models.DateTimeField(auto_now=False, null=True)
    last_seen = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        unique_together = (('address_ether', 'address_inet', 'origin',),)


class Socket(models.Model):
    interface = models.ForeignKey('Interface', related_name='sockets')
    port = models.IntegerField(default=0)
    protocol_l3 = models.IntegerField(default=0)
#    service_port = models.ForeignKey('config.Service', related_name='+', default=1)
#    service_detec = models.ForeignKey('config.Service', related_name='+', default=1)
    service_port = models.IntegerField(default=0)
    service_detec = models.IntegerField(default=0)

    class Meta:
        unique_together = (('interface', 'port', 'protocol_l3'),)


class Connection(models.Model):
    src_socket = models.ForeignKey('Socket', related_name='src_connections')
    dst_socket = models.ForeignKey('Socket', related_name='dst_connections')
    protocol_l4 = models.IntegerField(default=0)
    seq = models.BigIntegerField(default=-1, db_index=True)
    tx_pkts = models.BigIntegerField(default=0)
    tx_bytes = models.BigIntegerField(default=0)
    first_seen = models.DateTimeField(auto_now=False, null=True)
    last_seen = models.DateTimeField(auto_now=True, null=True)
    closed_flag = models.BooleanField(default=False)
    syn_flag = models.BooleanField(default=False)


class DNScache(models.Model):
    site = models.ForeignKey('config.Site', default=1)
    address_inet = models.GenericIPAddressField(db_index=True)
    name = models.CharField(max_length=253)
    type = models.CharField(max_length=15)
    last_seen = models.DateTimeField(auto_now=True)
