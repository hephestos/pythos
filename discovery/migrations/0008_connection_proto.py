# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0007_auto_20151017_1943'),
    ]

    operations = [
        migrations.AddField(
            model_name='connection',
            name='proto',
            field=models.IntegerField(default=-1, db_index=True),
        ),
    ]
