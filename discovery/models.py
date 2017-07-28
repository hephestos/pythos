from django.db import models
from macaddress.fields import MACAddressField

class Net(models.Model):
        """
        Stores a single IP network, related to :model:`config.Origin`, :model:`config.Site`, :model:`discovery.system`.
        """
        origin        = models.ForeignKey('config.Origin', null=True, blank=True)
        site          = models.ForeignKey('config.Site', null=True, blank=True)
        address_inet  = models.GenericIPAddressField(db_index=True, null=True, blank=True, help_text="IP network address")
        mask_inet     = models.GenericIPAddressField(db_index=True, null=True, blank=True, help_text="Subnet mask")
        mask_cidr     = models.IntegerField(null=True, help_text="CIDR prefix")
        address_bcast = models.GenericIPAddressField(db_index=True, null=True, blank=True, help_text="Broadcast address")
        gateway       = models.ForeignKey('Interface', null=True, related_name='gateway_for', help_text="Default gateway")
        netobjects    = models.ManyToManyField('architecture.NetObject', related_name='networks')


class System(models.Model):
        """
        Stores a single system in terms of a machine (be it physical or virtual).
        A system may be related to one or more instances of :model:`discovery.Interface`.
        """
        site          = models.ForeignKey('config.Site', null=True, blank=True)
        name          = models.CharField(max_length=127)
        description   = models.TextField()
        os            = models.ForeignKey('kb.OperatingSystem', null=True, blank=True, help_text="Operating system")


class Interface(models.Model):
        """
        Stores a single interface that may belong to exactly one :model:`discovery.System`.
        Further related to :model:`config.Origin`, :model:`discovery.System`, :model:`discovery.Net`, :model:`architecture.NetObject`.
        """
        origin        = models.ForeignKey('config.Origin', null=True, blank=True)
        system        = models.ForeignKey('System', null=True, blank=True)
        net           = models.ForeignKey('Net', null=True, blank=True)
        address_ether = MACAddressField(integer=False, null=True, blank=True, help_text="Ethernet (MAC) address")
        address_inet  = models.GenericIPAddressField(null=True, blank=True, help_text="IP (v4/v6) address", db_index=True)
        distance      = models.IntegerField(default=-1, help_text="Distance (in hops) from the origin (sensor)")
        protocol_l3   = models.IntegerField(default=0, help_text="OSI layer three protocol")
        tx_pkts       = models.BigIntegerField(default=0, help_text="Number of transmitted packets")
        tx_bytes      = models.BigIntegerField(default=0, help_text="Number of transmitted bytes")
        rx_pkts       = models.BigIntegerField(default=0, help_text="Number of received packets")
        rx_bytes      = models.BigIntegerField(default=0, help_text="Number of received bytes")
        ttl_seen      = models.IntegerField(default=0, help_text="TTL of transmitted packages as seen at the origin (sensor)")
        first_seen    = models.DateTimeField(auto_now=False, null=True, help_text="Timestamp of first occurence")
        last_seen     = models.DateTimeField(auto_now=False, null=True, help_text="Timestamp of last occurence")
        netobjects    = models.ManyToManyField('architecture.NetObject', related_name='interfaces')
        is_global     = models.NullBooleanField(null=True)
        is_private    = models.NullBooleanField(null=True)
        is_multicast  = models.NullBooleanField(null=True)
        is_unspecified = models.NullBooleanField(null=True)
        is_reserved = models.NullBooleanField(null=True)
        is_loopback = models.NullBooleanField(null=True)
        is_link_local = models.NullBooleanField(null=True)

        class Meta:
                unique_together = (('address_ether', 'address_inet', 'origin', 'ttl_seen'),)


class Socket(models.Model):
        """
        Stores a single socket that must belong to exactly one :model:`discovery.Interface`.
        """
        interface     = models.ForeignKey('Interface', related_name='sockets')
        port          = models.IntegerField(default=0)
        protocol_l4   = models.IntegerField(default=0, help_text="OSI layer four protocol")
        services      = models.ManyToManyField('architecture.Service', related_name='sockets')
        service_port  = models.IntegerField(default=0)
        service_detec = models.IntegerField(default=0)
        class Meta:
                unique_together = (('interface', 'port', 'protocol_l4'),)
                index_together = ['port', 'protocol_l4']


class Connection(models.Model):
        """
        Stores a single connection between two instances of :model:`discovery.Socket`.
        """
        src_socket    = models.ForeignKey('Socket', related_name='src_connections')
        dst_socket    = models.ForeignKey('Socket', related_name='dst_connections')
        protocol_l567 = models.IntegerField(default=-1)
        seq           = models.BigIntegerField(default=-1, db_index=True)
        tx_pkts       = models.BigIntegerField(default=0)
        tx_bytes      = models.BigIntegerField(default=0)
        first_seen    = models.DateTimeField(auto_now=False, null=True)
        last_seen     = models.DateTimeField(auto_now=True, null=True)
        closed_flag   = models.BooleanField(default=False)
        syn_flag      = models.BooleanField(default=False)
        class Meta:
                unique_together = (('src_socket', 'dst_socket', 'protocol_l567'),)


class DNScache(models.Model):
        """
        DEPRECATED
        Was used to store a captured DNS query. Will be migrated to :model:`discovery.System` as DNS names are stored there.
        """
        site          = models.ForeignKey('config.Site', default=1)
        address_inet  = models.GenericIPAddressField(db_index=True)
        name          = models.CharField(max_length=253)
        type	      = models.CharField(max_length=15)
        last_seen     = models.DateTimeField(auto_now=True)
