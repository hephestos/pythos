import uuid

from django.db import models
from macaddress.fields import MACAddressField


class Site(models.Model):
        """
        Stores a single site location of an organization.
        """
        code          = models.CharField(max_length=253, null=True)
        name          = models.CharField(max_length=253, null=True)
        company       = models.CharField(max_length=253, null=True)
        building      = models.CharField(max_length=253, null=True)
        street        = models.CharField(max_length=253, null=True)
        city          = models.CharField(max_length=253, null=True)
        state         = models.CharField(max_length=253, null=True)
        country       = models.CharField(max_length=253, null=True)
        region        = models.CharField(max_length=253, null=True)
        description   = models.TextField(null=True)


class Interface(models.Model):
        """
        Stores a single interface of a pythos node used for network capture.
        """
        name          = models.CharField(max_length=253)
        address_ether = models.CharField(max_length=17)


#class Service(models.Model):
#        port          = models.IntegerField(default=0)
#        name          = models.CharField(max_length=253)
#        description   = models.TextField(null=True)
#
#
#class Vendor(models.Model):
#        name          = models.CharField(max_length=253)
#        address_ether = MACAddressField(null=True)
#
#
class Origin(models.Model):
        """
        Stores a single origin of information of any kind. Information may be obtained from network capture of raw packets or netflow data as well as imported log files or manual entry. This model is agnostic of the actual source of information and just serves as a catalouge of information origins.
        Origins may be assigned a higher trustworthiness than the the default value of 0. Should information about an object be available from different origins, the higher trustworthiness is given preference.
        """
        uuid          = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
        name          = models.CharField(max_length=253)
        description   = models.TextField(null=True)
        trustworthiness = models.IntegerField(default=0)
        manual_flag   = models.BooleanField()
        sensor_flag   = models.BooleanField()
        import_flag   = models.BooleanField()

