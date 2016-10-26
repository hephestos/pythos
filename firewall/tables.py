import django_tables2 as tables
from firewall.models import Rule

# These classes are used in views.py

class RulesetTable(tables.Table):

    class Meta:
        fields = ['number', 'name', 'action', 'all_services', 'all_srcs', 'all_dsts']
        model = Rule
        # add class="paleblue" to <table> tag
        attrs = {"class": "paleblue"}
