from django.db import models


class Firewall(models.Model):
        name = models.TextField()


class Rule(models.Model):
        firewall = models.ForeignKey('Firewall', related_name='rules')
        name = models.TextField()
        number = models.IntegerField()
        action = models.CharField(max_length=6)
        services = models.ManyToManyField('kb.ServiceName', related_name='destinations')
        srcs = models.ManyToManyField('architecture.NetObject', related_name='src_rules')
        dsts = models.ManyToManyField('architecture.NetObject', related_name='dst_rules')


class Log(models.Model):
        src_file = models.CharField(max_length=256)


class Hit(models.Model):
        firewall = models.ForeignKey('Firewall', related_name='hits')
        log = models.ForeignKey('Log', related_name='hits')
        rule = models.ForeignKey('Rule', related_name='hits')
        src_service = models.ForeignKey('kb.ServiceName', related_name='sources')
        user = models.CharField(max_length=256)
        src_machine_name = models.CharField(max_length=255)
        src_user_name = models.CharField(max_length=255)
