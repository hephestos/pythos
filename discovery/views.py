from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.template import RequestContext, loader
from django.views import generic
from macaddress import format_mac
from django_tables2 import RequestConfig
from django.shortcuts import render_to_response
from django.db.models import Sum, Min, Max

import netifaces
import pyshark
import time, datetime, random

from .models import Interface, Connection
from .forms import ControlForm, PcapForm
from .tasks import DiscoveryTask

from discovery.tables import ConversationsTable

# Overview of identified systems
class IndexView(generic.ListView):
    template_name = 'discovery/index.html'
    # Interface in terms of an interface belonging to an identified system (NOT the interface used for capturing traffic)
    context_object_name = 'interface_list'

    def get_queryset(self):
        return Interface.objects.order_by('address_inet')

# Discovery control interface (trigger to capture traffic on specific interfaces)
def ControlView(request):
    if request.method == 'POST':
        form = ControlForm(request.POST)
        if form.is_valid():
            capture_interface = form.cleaned_data['interface']
            capture_duration = form.cleaned_data['duration']
            # Start Celery task
            DiscoveryTask.delay(origin_uuid="d44d8aa8c5ef495f992d7531336784fe",
                                offline=False,
                                interface=capture_interface,
                                duration=capture_duration)

            return render(request, 'discovery/control.html', {'form': form})
    else:
            form = ControlForm()

    return render(request, 'discovery/control.html', {'form': form})

# Process PCAP files from predefined folder for analysis
def PcapView(request):
    if request.method == 'POST':
        form = PcapForm(request.POST)
        if form.is_valid():
            filepath = form.cleaned_data['filepath']
            description = form.cleaned_data['origin_description']
            # Start Celery task
            DiscoveryTask(offline = True,
                          filepath = filepath,
                          origin_description = description)

            return render(request, 'discovery/pcap.html', {'form': form})
    else:
        form = PcapForm()

    return render(request, 'discovery/pcap.html', {'form': form})

# Overview of identified systems as table (same as IndexView) - but something is happening here with charts in near future ...
def EndpointsView(request):
    interface_objects = Interface.objects.values(
                            'address_inet',
                            'address_ether',
                            'ttl_seen',
                        ).annotate(
                            bytes_total = Sum('tx_bytes',fields='tx_bytes+rx_bytes'),
                            first_seen  = Min('first_seen'),
                            last_seen   = Max('last_seen'),
                        ).order_by('-bytes_total')

    # prepare barchart
    xdata = interface_objects.values_list('address_inet', flat = True)[:10]
    ydata = interface_objects.values_list('bytes_total',  flat = True)[:10]

    extra_serie1 = {"tooltip": {"y_start": "", "y_end": " cal"}}
    chartdata = {
        'x': xdata, 'name1': '', 'y1': ydata
    }
    charttype = "discreteBarChart"
    chartcontainer = 'barchart_container'
    data = {
        'charttype': charttype,
        'chartdata': chartdata,
        'chartcontainer': chartcontainer,
    }

    return render(
            request,
            'discovery/endpoints.html',
            {
               'endpoints': interface_objects,
                'charttype': charttype,
                'chartdata': chartdata,
                'chartcontainer': chartcontainer
             }
         )

# Overview of identified conversations (per ip addresses and used ports in both directions)
def ConversationsView(request):
    table = ConversationsTable(Connection.objects.all())
    RequestConfig(request).configure(table)
    return render(request, 'discovery/conversations.html', {'table': table})
