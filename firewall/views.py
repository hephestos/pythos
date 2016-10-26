from django.shortcuts import render
from django.views import generic

from django_tables2 import RequestConfig

from .models import Firewall, RuleSet, Rule

from firewall.tables import RulesetTable

def ruleset(request, firewall_id, ruleset_id):
    rules = Rule.objects.filter(ruleset=ruleset_id, ruleset__firewall=firewall_id)
    table = RulesetTable(rules)
    RequestConfig(request, paginate={'per_page': 50}).configure(table)
    return render(request, 'firewall/ruleset.html', {'table': table})
