# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import macaddress.fields


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0005_auto_20151017_1752'),
    ]

    operations = [
        migrations.AlterField(
            model_name='host',
            name='address_ether',
            field=macaddress.fields.MACAddressField(null=True, db_index=True, blank=True, integer=True),
        ),
        migrations.AlterField(
            model_name='host',
            name='address_inet',
            field=models.GenericIPAddressField(db_index=True),
        ),
        migrations.AlterField(
            model_name='net',
            name='address_inet',
            field=models.GenericIPAddressField(db_index=True),
        ),
        migrations.AlterField(
            model_name='net',
            name='mask_inet',
            field=models.GenericIPAddressField(db_index=True),
        ),
        migrations.AlterField(
            model_name='port',
            name='port',
            field=models.IntegerField(default=0, db_index=True),
        ),
    ]
