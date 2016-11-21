from django.db import models


class Firewall(models.Model):
        name = models.TextField()


class RuleSet(models.Model):
        firewall = models.ForeignKey('Firewall', related_name='rulesets')
        description = models.CharField(max_length=255)


class Rule(models.Model):
        ruleset = models.ForeignKey('RuleSet', related_name='rules')
        name = models.TextField()
        number = models.IntegerField()
        action = models.CharField(max_length=16)
        services = models.ManyToManyField('kb.ServiceName', related_name='rules')
        srcs = models.ManyToManyField('architecture.NetObject', related_name='src_rules')
        dsts = models.ManyToManyField('architecture.NetObject', related_name='dst_rules')

        @property
        def all_services(self):
            return ', '.join([x.port for x in self.services.all().order_by('port')])

        @property
        def all_srcs(self):
            return ', '.join([x.name for x in self.srcs.all().order_by('name')])

        @property
        def all_dsts(self):
            return ', '.join([x.name for x in self.dsts.all().order_by('name')])

        @property
        def all_interfaces(self):
            return ', '.join([x.interface for x in self.hits.all().order_by('interface').distinct('interface')])


class Log(models.Model):
        src_file = models.CharField(max_length=256)
        import_time = models.DateTimeField(auto_now=True)


class Hit(models.Model):
        log = models.ForeignKey('Log', related_name='hits')
        rule = models.ForeignKey('Rule', related_name='hits')
        src = models.ForeignKey('architecture.NetObject', related_name='src_hits')
        src_service = models.ForeignKey('kb.ServiceName', related_name='src_hits')
        dst = models.ForeignKey('architecture.NetObject', related_name='dst_hits')
        dst_service = models.ForeignKey('kb.ServiceName', related_name='dst_hits')
        hit_time = models.DateTimeField(auto_now=False, null=True)
        interface = models.CharField(max_length=127)
        user = models.CharField(max_length=255)
        src_machine_name = models.CharField(max_length=255)
        src_user_name = models.CharField(max_length=255)
