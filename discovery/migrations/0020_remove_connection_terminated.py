# -*- coding: utf-8 -*-
# Generated by Django 1.9.1 on 2016-03-18 00:36
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0019_auto_20160318_0035'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='connection',
            name='terminated',
        ),
    ]
