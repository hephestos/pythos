# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('config', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Connection',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
            ],
        ),
        migrations.CreateModel(
            name='Host',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('name', models.CharField(max_length=127)),
                ('distance', models.IntegerField(default=0)),
            ],
        ),
        migrations.CreateModel(
            name='Net',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('site', models.ForeignKey(to='config.Site')),
            ],
        ),
        migrations.CreateModel(
            name='Port',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('port', models.IntegerField(default=0)),
                ('host', models.ForeignKey(to='discovery.Host')),
                ('service', models.ForeignKey(related_name='+', to='config.Service')),
            ],
        ),
        migrations.AddField(
            model_name='host',
            name='net',
            field=models.ForeignKey(to='discovery.Net'),
        ),
        migrations.AddField(
            model_name='connection',
            name='dst_port',
            field=models.ForeignKey(related_name='+', to='discovery.Port'),
        ),
        migrations.AddField(
            model_name='connection',
            name='src_port',
            field=models.ForeignKey(related_name='+', to='discovery.Port'),
        ),
    ]
