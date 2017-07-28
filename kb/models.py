from django.db import models
from macaddress.fields import MACAddressField


class EtherOUI(models.Model):
        oui           = MACAddressField(null=True, blank=True, db_index=True)
        vendor        = models.CharField(max_length=253)

class ServiceName(models.Model):
        name          = models.CharField(max_length=127)
        protocol_l3   = models.CharField(max_length=127, db_index=True)
        port          = models.CharField(max_length=127, null=True, db_index=True)
        description   = models.TextField()
        class Meta:
                unique_together = (('port','protocol_l3'),)

class OperatingSystem(models.Model):
        vendor        = models.CharField(max_length=127)
        product       = models.CharField(max_length=127)
        default_ttl   = models.IntegerField(default=-1)

class Template(models.Model):
        name          = models.CharField(max_length=127)
        services      = models.ManyToManyField('ServiceName', related_name='Templates')
        services_match_percent = models.IntegerField(default=-1)
        services_min_count     = models.IntegerField(default=1)
        clients_min_count      = models.IntegerField(default=1)
        clients_min_conns      = models.IntegerField(default=1)

class Application(models.Model):
        name          = models.CharField(max_length=127)
        description   = models.TextField(null=True, blank=True)
        servers       = models.ManyToManyField('discovery.Socket', related_name='application_server')
        clients       = models.ManyToManyField('discovery.Socket', related_name='application_client')
        service       = models.ManyToManyField('ServiceName', related_name='Applications')
        template      = models.ForeignKey('Template', related_name='Applications', null=True)
