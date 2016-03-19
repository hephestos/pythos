# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import macaddress.fields


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='host',
            name='address_ether',
            field=macaddress.fields.MACAddressField(blank=True, null=True, integer=True),
        ),
    ]
