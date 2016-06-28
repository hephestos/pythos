from django.db import models

class Firewall(models.Model):
        name = models.TextField()

class Rule(models.Model):
        firewall = models.ForeignKey('Firewall', related_name='rules')
        name = model.TextField()
        src = models.ForeignKey('architecture.NetObject', related_name='src_rules')
        dst = models.ForeignKey('architecture.NetObject', related_name='dst_rules')
        protocol = models.IntegerField(default=0)
        port = models.IntegerField(default=0)
