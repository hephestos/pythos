# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import datetime
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0002_host_address_ether'),
    ]

    operations = [
        migrations.AddField(
            model_name='host',
            name='address_inet',
            field=models.GenericIPAddressField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='host',
            name='description',
            field=models.TextField(),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='host',
            name='last_seen',
            field=models.DateTimeField(default=datetime.datetime(2015, 10, 15, 19, 54, 14, 152940, tzinfo=utc), auto_now=True),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='net',
            name='address_inet',
            field=models.GenericIPAddressField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='net',
            name='mask_inet',
            field=models.GenericIPAddressField(default=0),
            preserve_default=False,
        ),
    ]
