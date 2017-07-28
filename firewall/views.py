from django.shortcuts import render
from django.views import generic
from django.db.models import Count

from django_tables2 import RequestConfig
from eztables.views import DatatablesView

from firewall.models import Firewall, RuleSet, Rule, Hit
from kb.models import ServiceName

from firewall.tables import RulesetTable, RuleTable

def ruleset(request, firewall_id, ruleset_id):
    rules = Rule.objects.filter(ruleset=ruleset_id, ruleset__firewall=firewall_id, disabled=False).annotate(hitcounter=Count('hits')).order_by('number')
    table = RulesetTable(rules)
#    RequestConfig(request, paginate={'per_page': 50}).configure(table)
    return render(request, 'firewall/ruleset.html', {'table': table})

def rule(request, firewall_id, ruleset_id, rule_id):
    rule_object = Rule.objects.get(id=rule_id, ruleset=ruleset_id, ruleset__firewall=firewall_id)
    rule_number = rule_object.number
    rule_name = rule_object.name

    hits = Hit.objects.filter(rule=rule_id, rule__ruleset=ruleset_id, rule__ruleset__firewall=firewall_id).order_by('dst__name', 'dst_service__port', 'src__name').distinct('dst__name', 'dst_service__port', 'src__name')
    table = RuleTable(hits)

#    RequestConfig(request, paginate={'per_page': 50}).configure(table)
    return render(request, 'firewall/rule.html', {'table': table, 'rule_number': rule_number, 'rule_name': rule_name})
