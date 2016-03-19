from django.db import models
from macaddress.fields import MACAddressField

class Net(models.Model):
        site          = models.ForeignKey('config.Site', default=1)
        address_inet  = models.GenericIPAddressField(db_index=True, null=True, blank=True)
        mask_inet     = models.GenericIPAddressField(db_index=True, null=True, blank=True)
        address_bcast = models.GenericIPAddressField(db_index=True, null=True, blank=True)
        gateway       = models.ForeignKey('Host', null=True, related_name='+')
        name_server   = models.ForeignKey('Host', null=True, related_name='+')

class Host(models.Model):
        site          = models.ForeignKey('config.Site', default=1)
        name          = models.CharField(max_length=127)
        description   = models.TextField()

class Interface(models.Model):
        sensor        = models.ForeignKey('config.Sensor')
        host          = models.ForeignKey('Host', null=True, blank=True)
        net           = models.ForeignKey('Net', null=True, blank=True)
        address_ether = MACAddressField(null=True, blank=True, db_index=True)
        address_inet  = models.GenericIPAddressField(null=True, blank=True, db_index=True)
        distance      = models.IntegerField(default=0)
        tx_pkts       = models.BigIntegerField(default=0)
        tx_bytes      = models.BigIntegerField(default=0)
        rx_pkts       = models.BigIntegerField(default=0)
        rx_bytes      = models.BigIntegerField(default=0)
        first_seen    = models.DateTimeField(auto_now=False, null=True)
        last_seen     = models.DateTimeField(auto_now=True, null=True)
        class Meta:
                unique_together = (('address_ether', 'address_inet', 'sensor'),)

class Port(models.Model):
        interface     = models.ForeignKey('Interface')
        port          = models.IntegerField(default=0, db_index=True)
        proto         = models.IntegerField(default=-1, db_index=True)
        service       = models.ForeignKey('config.Service', related_name='+', default=1)
        class Meta:
                unique_together = (('interface', 'port', 'proto'),)

class Connection(models.Model):
        src_port      = models.ForeignKey('Port', related_name='+')
        dst_port      = models.ForeignKey('Port', related_name='+')
        proto         = models.IntegerField(default=-1, db_index=True)
        seq           = models.BigIntegerField(default=-1, db_index=True)
        tx_pkts       = models.BigIntegerField(default=0)
        tx_bytes      = models.BigIntegerField(default=0)
        first_seen    = models.DateTimeField(auto_now=False, null=True)
        last_seen     = models.DateTimeField(auto_now=True, null=True)
        class Meta:
                unique_together = (('src_port', 'dst_port', 'proto'),)

class DNScache(models.Model):
        site          = models.ForeignKey('config.Site', default=1)
        address_inet  = models.GenericIPAddressField(db_index=True)
        name          = models.CharField(max_length=253)
        last_seen     = models.DateTimeField(auto_now=True)
