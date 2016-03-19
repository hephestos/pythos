# -*- coding: utf-8 -*-
# Generated by Django 1.9.1 on 2016-03-17 23:29
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion
import macaddress.fields


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0015_auto_20160316_2220'),
    ]

    operations = [
        migrations.CreateModel(
            name='Interface',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('address_ether', macaddress.fields.MACAddressField(blank=True, db_index=True, integer=True, null=True)),
                ('address_inet', models.GenericIPAddressField(blank=True, db_index=True, null=True)),
                ('distance', models.IntegerField(default=0)),
                ('tx_pkts', models.BigIntegerField(default=0)),
                ('tx_bytes', models.BigIntegerField(default=0)),
                ('rx_pkts', models.BigIntegerField(default=0)),
                ('rx_bytes', models.BigIntegerField(default=0)),
                ('first_seen', models.DateTimeField(auto_now=True, null=True)),
                ('last_seen', models.DateTimeField(auto_now=True, null=True)),
            ],
        ),
        migrations.RemoveField(
            model_name='port',
            name='host',
        ),
        migrations.AddField(
            model_name='connection',
            name='first_seen',
            field=models.DateTimeField(auto_now=True, null=True),
        ),
        migrations.AlterField(
            model_name='connection',
            name='last_seen',
            field=models.DateTimeField(auto_now=True, null=True),
        ),
        migrations.AlterUniqueTogether(
            name='host',
            unique_together=set([]),
        ),
        migrations.AddField(
            model_name='interface',
            name='host',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='discovery.Host'),
        ),
        migrations.AddField(
            model_name='interface',
            name='net',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='discovery.Net'),
        ),
        migrations.RemoveField(
            model_name='host',
            name='address_ether',
        ),
        migrations.RemoveField(
            model_name='host',
            name='address_inet',
        ),
        migrations.RemoveField(
            model_name='host',
            name='distance',
        ),
        migrations.RemoveField(
            model_name='host',
            name='last_seen',
        ),
        migrations.RemoveField(
            model_name='host',
            name='net',
        ),
        migrations.AddField(
            model_name='port',
            name='interface',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='discovery.Interface'),
            preserve_default=False,
        ),
        migrations.AlterUniqueTogether(
            name='interface',
            unique_together=set([('address_ether', 'address_inet')]),
        ),
    ]
