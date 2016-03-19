# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0009_auto_20151017_2025'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='connection',
            unique_together=set([('src_port', 'dst_port', 'proto')]),
        ),
    ]
