# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import datetime
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0012_dnscache'),
    ]

    operations = [
        migrations.AddField(
            model_name='dnscache',
            name='last_seen',
            field=models.DateTimeField(auto_now=True, default=datetime.datetime(2015, 10, 18, 0, 18, 43, 818425, tzinfo=utc)),
            preserve_default=False,
        ),
    ]
