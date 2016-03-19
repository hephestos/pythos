# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0013_dnscache_last_seen'),
    ]

    operations = [
        migrations.AddField(
            model_name='connection',
            name='terminated',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='net',
            name='address_bcast',
            field=models.GenericIPAddressField(blank=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name='net',
            name='gateway',
            field=models.ForeignKey(null=True, to='discovery.Host', related_name='+'),
        ),
        migrations.AddField(
            model_name='net',
            name='name_server',
            field=models.ForeignKey(null=True, to='discovery.Host', related_name='+'),
        ),
        migrations.AlterField(
            model_name='net',
            name='address_inet',
            field=models.GenericIPAddressField(blank=True, db_index=True, null=True),
        ),
        migrations.AlterField(
            model_name='net',
            name='mask_inet',
            field=models.GenericIPAddressField(blank=True, db_index=True, null=True),
        ),
    ]
