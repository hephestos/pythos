import django_tables2 as tables
from django_tables2 import A
from django.db.models import Count

from firewall.models import Rule, Hit
from kb.models import ServiceName

# These classes are used in views.py

class RulesetTable(tables.Table):

    class Meta:
        fields = ['id', 'number', 'all_interfaces', 'name', 'action', 'all_services', 'all_srcs', 'all_dsts', 'hitcounter']
        model = Rule
        # add class="paleblue" to <table> tag
        attrs = {"class": "paleblue"}


class RuleTable(tables.Table):
    src_name = tables.Column(accessor='src.name', verbose_name="source")
    dst_name = tables.Column(accessor='dst.name', verbose_name="destination")
    dst_port = tables.Column(accessor='dst_service.port', verbose_name="service")
    dst_proto = tables.Column(accessor='dst_service.protocol_l3', verbose_name='protocol')
    hitcounter = tables.Column(accessor='Count(self)', verbose_name='hits')

    class Meta:
        fields = ['src_name','dst_name','dst_port', 'dst_proto', 'hitcounter']
        model = Hit
        # add class="paleblue" to <table> tag
        attrs = {"class": "paleblue"}
