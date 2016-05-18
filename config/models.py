import uuid

from django.db import models
from macaddress.fields import MACAddressField

class Site(models.Model):
        name          = models.CharField(max_length=127)
        description   = models.TextField(null=True)

class Interface(models.Model):
        name          = models.CharField(max_length=127)
        address_ether = models.CharField(max_length=17)

class Service(models.Model):
        port          = models.IntegerField(default=0)
        name          = models.CharField(max_length=127)
        description   = models.TextField(null=True)

class Vendor(models.Model):
        name          = models.CharField(max_length=127)
        address_ether = MACAddressField(null=True)

class Origin(models.Model):
        uuid          = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
        name          = models.CharField(max_length=127)
        description   = models.TextField(null=True)
        sensor_flag   = models.BooleanField()
        plant_flag    = models.BooleanField()
