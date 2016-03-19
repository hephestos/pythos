# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0006_auto_20151017_1908'),
    ]

    operations = [
        migrations.AddField(
            model_name='connection',
            name='seq',
            field=models.BigIntegerField(default=-1),
        ),
        migrations.AlterField(
            model_name='port',
            name='service',
            field=models.ForeignKey(default=1, related_name='+', to='config.Service'),
        ),
    ]
