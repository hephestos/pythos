from django.db import models


class Partition(models.Model):
        """
        A partition is the highest logical layer in this network architecture.
        It comprises zones with a similar protection requirement.
        """
        layer = models.IntegerField(default=0, unique=True)
        name = models.TextField()


class Zone(models.Model):
        """
        A zone comprises one or several networks and is a member of
        exaclty one :model:`architecture.Partition`.
        """
        partition = models.ForeignKey('Partition', related_name='zones', null=True)
        name = models.TextField()


class NetObject(models.Model):
        """
        A network object is a member of exaclty one :model:`architecture.Zone`. It is an abstraction
        layer that may represent whole networks or individual hosts as well as subordinate network objects.
        It is used for the definition of packet filter rules and thus closely linked to :model:`firewall.Rule`.
        """
        children = models.ManyToManyField('self', symmetrical=False, related_name='parents')
        zone = models.ForeignKey('Zone', related_name='netobjects', null=True)
        name = models.TextField()

        class Meta:
            unique_together = (('name'),)


class Service(models.Model):
        """
#        A service object serves as a grouping layer for services :model:`architecture.Zone`. It is an abstraction
#        layer that may represent whole networks or individual hosts as well as subordinate network objects.
#        It is used for the definition of packet filter rules and thus closely linked to :model:`firewall.Rule`.
        """
        children = models.ManyToManyField('self', symmetrical=False, related_name='parents')
        name = models.TextField()
        description = models.TextField(null=True)
        category = models.TextField(null=True)
        proto_l4 = models.IntegerField(null=True)
        port_min = models.IntegerField(null=True)
        port_max = models.IntegerField(null=True)

        class Meta:
            unique_together = (('name'),)
            index_together = ['proto_l4', 'port_min', 'port_max']
