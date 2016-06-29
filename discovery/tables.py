import django_tables2 as tables
from discovery.models import Connection


# These classes are used in views.py
class ConversationsTable(tables.Table):
        src_port = tables.Column(accessor='src_socket.port')
        src_addr = tables.Column(accessor='src_socket.interface.address_ether')
        dst_port = tables.Column(accessor='dst_socket.port')
        dst_addr = tables.Column(accessor='dst_socket.interface.address_ether')

        class Meta:
                fields = ['src_addr',
                          'src_port',
                          'dst_addr',
                          'dst_port',
                          'tx_pkts',
                          'tx_bytes',
                          ]
                model = Connection
                # add class="paleblue" to <table> tag
                attrs = {"class": "paleblue"}
