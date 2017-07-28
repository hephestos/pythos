import django_tables2 as tables
from django_tables2 import A
from django.db.models import Count

from netflow.models import Flow

# These classes are used in views.py

class FlowTable(tables.Table):
    protocol = tables.Column(accessor='src.protocol_l4', verbose_name='Protocol (IP)')
    src_ip = tables.Column(accessor='src.interface.address_inet', verbose_name='Source IP')
    src_name = tables.Column(accessor='src.interface.system.name', verbose_name='Source Name')
    src_port = tables.Column(accessor='src.port', verbose_name='Source Port')
    src_os = tables.Column(accessor='src.interface.system.os.product', verbose_name='Source OS')
    src_dscr = tables.Column(accessor='src.interface.system.description', verbose_name='Source description')
    dst_ip = tables.Column(accessor='dst.interface.address_inet', verbose_name='Destination IP')
    dst_name = tables.Column(accessor='dst.interface.system.name', verbose_name='Destination Name')
    dst_port = tables.Column(accessor='dst.port', verbose_name='Destination Port')
    dst_os = tables.Column(accessor='dst.interface.system.os.product', verbose_name='Destination OS')
    dst_dscr = tables.Column(accessor='dst.interface.system.description', verbose_name='Destination description')

    class Meta:
        fields = ['protocol', 'src_ip', 'src_name', 'src_port', 'src_os', 'src_dscr', 'dst_ip', 'dst_name', 'dst_port', 'dst_os', 'dst_dscr', 'flow_count']
        model = Flow
        # add class="paleblue" to <table> tag
        attrs = {"class": "paleblue"}
