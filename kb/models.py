from django.db import models
from macaddress.fields import MACAddressField


class EtherOUI(models.Model):
        oui           = MACAddressField(null=True, blank=True, db_index=True)
        vendor        = models.CharField(max_length=253)

class ServiceName(models.Model):
        name          = models.CharField(max_length=127)
        port          = models.IntegerField(db_index=True)
        protocol_l3   = models.IntegerField(db_index=True)
        description   = models.TextField()
        class Meta:
                unique_together = (('port','protocol_l3'),)

class OperatingSystem(models.Model):
        vendor        = models.CharField(max_length=127)
        product       = models.CharField(max_length=127)
        default_ttl   = models.IntegerField()
