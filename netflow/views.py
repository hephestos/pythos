from django.shortcuts import render
from django.views import generic
from django.db.models import Count, F, Q

from django_tables2 import RequestConfig
from eztables.views import DatatablesView

from netflow.models import Flow
from config.models import Site
from kb.models import ServiceName
from discovery.models import Interface
from architecture.models import Service
from firewall.models import RuleSet, Rule

from netflow.tables import FlowTable


def flows(request, min_flow_count=1, ruleset=RuleSet.objects.get(id=61), site=Site.objects.get(id=503)):
    netflows = Flow.objects.filter(
                Q(src__interface__net__site=site) | Q(dst__interface__net__site=site),
                flow_count__gte=min_flow_count,
                src__protocol_l4__gt=0,
                dst__protocol_l4__gt=0,
                src__port__gte=F('dst__port'),
               )

#    services_for_ruleset = set(Service.objects.filter(rules__ruleset=ruleset, rules__action="accept").values_list('pk'))

#    netflows_without_rule = netflows.exclude(dst__services__in=services_for_ruleset)
#    for rule in Rule.objects.filter(ruleset=ruleset):
#        netflows = netflows.exclude(Q(dst__in=set(rule.dsts.values_list('interfaces__sockets'))) | Q(dst__in=set(rule.dsts.values_list('networks__interface__sockets'))),
#                                    Q(src__in=set(rule.srcs.values_list('interfaces__sockets'))) | Q(src__in=set(rule.srcs.values_list('networks__interface__sockets'))),
#                                   )
 
    netflows = netflows.order_by(
                'dst__interface__address_inet',
                'dst__port',
                'src__interface__address_inet',
                'src__port',
               ).values(
                'src',
                'src__protocol_l4',
                'src__interface__address_inet',
                'src__interface__system__name',
                'src__port',
                'src__interface__system__os__product',
                'src__interface__system__description',
                'src__interface__net__site__code',
                'dst',
                'dst__protocol_l4',
                'dst__interface__address_inet',
                'dst__interface__system__name',
                'dst__port',
                'dst__interface__system__os__product',
                'dst__interface__system__description',
                'dst__interface__net__site__code',
                'flow_count',
               )

    return render(request, 'netflow/flows.html', {'netflows': netflows})


def flows_single(request, min_flow_count=1, ruleset=None, site=Site.objects.filter(id=306)):
    netflows = Flow.objects.filter(log__id__gte=58, flow_count__gte=min_flow_count, src__protocol_l4__gt=0, dst__protocol_l4__gt=0, src__port__gte=F('dst__port')).order_by('dst__interface__address_inet', 'dst__port', 'src__interface__address_inet', 'src__port').values(
            'src',
            'src__protocol_l4',
            'src__interface__address_inet',
            'src__interface__system__name',
            'src__port',
            'src__interface__system__os__product',
            'src__interface__system__description',
            'src__interface__net__site__code',
            'dst',
            'dst__protocol_l4',
            'dst__interface__address_inet',
            'dst__interface__system__name',
            'dst__port',
            'dst__interface__system__os__product',
            'dst__interface__system__description',
            'dst__interface__net__site__code',
            'flow_count',
            )

    return render(request, 'netflow/flows_singlerow.html', {'netflows': netflows})
