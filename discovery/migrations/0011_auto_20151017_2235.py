# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0010_auto_20151017_2209'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='host',
            unique_together=set([('address_ether', 'address_inet')]),
        ),
    ]
