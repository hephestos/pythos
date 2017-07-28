from django.db import models


class Log(models.Model):
        """
        Stores one instance of a log imported from a file.
        """
        src_file = models.CharField(max_length=256, help_text="Path of the file the data was imported from. Used for human reference only.")
        src_hash_hex = models.CharField(max_length=128, help_text="SHA-512 hash hex representation of the file the data was imported from. Used to check if a file was re-imported.")
        import_time = models.DateTimeField(auto_now=True, help_text="Timestamp of the time of import")
        import_complete = models.BooleanField(default=False, help_text="Boolean value showing a complete import")


class Flow(models.Model):
        """
        Stores one single Netflow.
        A netflow instance is always derived from one :model:`netflow.Log`. Source and destination are references to instances of :model:`discovery.Socket`.
        """
        log = models.ForeignKey('Log', related_name='hits')
        src = models.ForeignKey('discovery.Socket', related_name='src_flows')
        dst = models.ForeignKey('discovery.Socket', related_name='dst_flows')
        bytes_in_volume = models.BigIntegerField(null=True)
        bytes_in_rate = models.FloatField(null=True)
        bytes_in_percent = models.FloatField(null=True)
        flow_count = models.BigIntegerField(null=True, db_index=True)
        packets_in_volume = models.BigIntegerField(null=True)
        packets_in_rate = models.FloatField(null=True)
        packets_in_percent = models.FloatField(null=True)
