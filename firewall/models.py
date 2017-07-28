from django.db import models


class Firewall(models.Model):
        """
        Stores a single firewall, related to :model:`firewall.RuleSet`.
        """
        name = models.TextField()


class RuleSet(models.Model):
        """
        Stores a single firewall rule set, related to :model:`firewall.Firewall` and :model:`firewall.Rule`.
        """
        firewall = models.ForeignKey('Firewall', related_name='rulesets')
        description = models.CharField(max_length=255)


class Rule(models.Model):
        """
        Stores a single firewall rule, related to :model:`firewall.RuleSet`, :model:`kb.ServiceName` and :model:`architecture.NetObject`.
        """
        ruleset = models.ForeignKey('RuleSet', related_name='rules')
        name = models.TextField(null=True)
        uuid = models.CharField(max_length=64, null=True)
        number = models.IntegerField(null=True, help_text="Rule number as used on the firewall during the time of import. May change if rules are added or removed.")
        action = models.CharField(max_length=16, db_index=True)
        services = models.ManyToManyField('architecture.Service', related_name='rules')
        srcs = models.ManyToManyField('architecture.NetObject', related_name='src_rules')
        dsts = models.ManyToManyField('architecture.NetObject', related_name='dst_rules')
        disabled = models.BooleanField(default=False)

        @property
        def all_services(self):
            return ', '.join([x.name for x in self.services.all().order_by('port_min')])

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
        """
        Stores one instance of a log imported from a file.
        """
        src_file = models.CharField(max_length=256)
        src_hash_hex = models.CharField(max_length=128, help_text="SHA-512 hash hex representation of the file the data was imported from. Used to check if a file was re-imported.")
        import_time = models.DateTimeField(auto_now=True)
        import_complete = models.BooleanField(default=False, help_text="Boolean value showing a complete import")


class Hit(models.Model):
        """
        Stores a single hit to a firewall rule. This is used to store the data from imported firewall logs.
        Related to :model:`firewall.Log`, :model:`firewall.rule`, :model:`architecture.NetObject` and :model:`kb.ServiceName`.
        """
        log = models.ForeignKey('Log', related_name='hits')
        rule = models.ForeignKey('Rule', related_name='hits')
        src = models.ForeignKey('architecture.NetObject', related_name='src_hits')
        src_service = models.ForeignKey('kb.ServiceName', related_name='src_hits')
        dst = models.ForeignKey('architecture.NetObject', related_name='dst_hits')
        dst_service = models.ForeignKey('kb.ServiceName', related_name='dst_hits')
        hit_time = models.DateTimeField(auto_now=False, null=True)
        interface = models.CharField(max_length=127, null=True, help_text="The name of the interface on the firewall which was used by this hit.")
        user = models.CharField(max_length=255, null=True, help_text="??? Used by Check Point.")
        src_machine_name = models.CharField(max_length=255, null=True, help_text="??? Used by Check Point.")
        src_user_name = models.CharField(max_length=255, null=True, help_text="??? Used by Check Point.")
