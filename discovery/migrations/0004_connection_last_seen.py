# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import datetime
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0003_auto_20151015_1954'),
    ]

    operations = [
        migrations.AddField(
            model_name='connection',
            name='last_seen',
            field=models.DateTimeField(default=datetime.datetime(2015, 10, 15, 23, 6, 54, 271052, tzinfo=utc), auto_now=True),
            preserve_default=False,
        ),
    ]
