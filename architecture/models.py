from django.db import models

# A partition is the highest logical layer in this network architecture.
# It comprises zones with a similar protection requirement
class Partition(models.Model):
        layer = models.IntegerField(default=0, unique=True)
        name = models.TextField()

# A zone comprises one or several networks and is a member of
# exaclty one partition
class Zone(models.Model):
        partition = models.ForeignKey('Partition', related_name='zones', null=True)
        name = models.TextField()

# A network object is a member of exaclty one zone. It is an abstraction
# layer that may represent whole networks or individual hosts. In this context,
# a host is always an end device (e.g. client or server), but never an
# intermediary device (e.g. router). It is used for the definition of
# packet filter rules.
class NetObject(models.Model):
        zone = models.ForeignKey('Zone', related_name='netobjects', null=True)
        name = models.TextField()

# Here, a network is a member of excatly one network object
class Network(models.Model):
        netobject = models.ForeignKey('NetObject', related_name='networks', null=True)
        network = models.ForeignKey('discovery.Net', related_name='netobject', null=True)

# Here, a host is a member of excatly one network object
class Host(models.Model):
        netobject = models.ForeignKey('NetObject', related_name='hosts', null=True)
        host = models.ForeignKey('discovery.System', related_name='netobject', null=True)
