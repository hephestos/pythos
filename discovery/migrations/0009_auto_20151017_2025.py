# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0008_connection_proto'),
    ]

    operations = [
        migrations.AddField(
            model_name='port',
            name='proto',
            field=models.IntegerField(default=-1, db_index=True),
        ),
        migrations.AlterField(
            model_name='connection',
            name='seq',
            field=models.BigIntegerField(default=-1, db_index=True),
        ),
    ]
