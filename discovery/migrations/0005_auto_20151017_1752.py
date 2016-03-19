# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import discovery.models


class Migration(migrations.Migration):

    dependencies = [
        ('config', '0001_initial'),
        ('discovery', '0004_connection_last_seen'),
    ]

    operations = [
        migrations.AddField(
            model_name='host',
            name='site',
            field=models.ForeignKey(default=1, to='config.Site'),
        ),
        migrations.AlterField(
            model_name='net',
            name='site',
            field=models.ForeignKey(default=1, to='config.Site'),
        ),
    ]
