# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('config', '0001_initial'),
        ('discovery', '0011_auto_20151017_2235'),
    ]

    operations = [
        migrations.CreateModel(
            name='DNScache',
            fields=[
                ('id', models.AutoField(primary_key=True, auto_created=True, verbose_name='ID', serialize=False)),
                ('address_inet', models.GenericIPAddressField(db_index=True)),
                ('name', models.CharField(max_length=253)),
                ('site', models.ForeignKey(default=1, to='config.Site')),
            ],
        ),
    ]
