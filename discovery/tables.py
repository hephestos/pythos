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


class IdentifyCentralSystemsTable(tables.Table):
        port = tables.Column(accessor='dst_socket__port')
        dst_ip_addr = tables.Column(accessor='dst_socket__interface__address_inet')
        src_ip_addr = tables.Column(accessor='src_socket__interface__address_inet')
        dest_ip_counter = tables.Column(accessor='dest_ip_counter')

        class Meta:
                fields = ['dst_ip_addr',
                          'src_ip_addr',
                          'port',
                          'dest_ip_counter',
                        ]
                model = Connection
                attrs = {"class": "paleblue"}
