from django.shortcuts import render
from django.views import generic
from django_tables2 import RequestConfig
from django.db.models import Sum, Min, Max, Count

from redis import Redis
from rq import Queue

from .models import Interface, Connection
from .forms import ControlForm, PcapForm
from .tasks import discovery_task

from discovery.tables import ConversationsTable
from discovery.tables import IdentifyCentralSystemsTable


# Overview of identified systems
class IndexView(generic.ListView):
    template_name = 'discovery/index.html'
    context_object_name = 'interface_list'

    def get_queryset(self):
        return Interface.objects.order_by('address_inet')


# Discovery control (trigger to capture traffic on specific interface)
def ControlView(request):
    if request.method == 'POST':
        form = ControlForm(request.POST)
        if form.is_valid():
            capture_interface = form.cleaned_data['interface']
            capture_duration = form.cleaned_data['duration']

            discovery_task.delay(origin_uuid="d44d8aa8c5ef495f992d7531336784fe",
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
            description = "pcap"  # form.cleaned_data['origin_description']

            discovery_task.delay(offline=True,
                                 filepath=filepath,
                                 origin_description=description)

            return render(request, 'discovery/pcap.html', {'form': form})
    else:
        form = PcapForm()

    return render(request, 'discovery/pcap.html', {'form': form})


# Overview of identified systems as table (same as IndexView)
# Something will happen here with charts in near future
def EndpointsView(request):
    interface_objects = Interface.objects.values(
                            'address_inet',
                            'address_ether',
                            'ttl_seen',
                        ).annotate(
                            bytes_total=Sum('tx_bytes',
                                            fields='tx_bytes+rx_bytes'),
                            first_seen=Min('first_seen'),
                            last_seen=Max('last_seen'),
                        ).order_by('-bytes_total')

    # prepare barchart
    xdata = interface_objects.values_list('address_inet', flat=True)[:10]
    ydata = interface_objects.values_list('bytes_total',  flat=True)[:10]

    chartdata = {
        'x': xdata, 'name1': '', 'y1': ydata
    }
    charttype = "discreteBarChart"
    chartcontainer = 'barchart_container'

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


# Overview of identified conversations
# Per IP address and used ports in both directions
def ConversationsView(request):
    table = ConversationsTable(Connection.objects.all())
    RequestConfig(request).configure(table)
    return render(request, 'discovery/conversations.html', {'table': table})


# Queries: Identify central systems (by amount of connections to one system)
def QueriesView(request):
    # Result table with overview
    table = IdentifyCentralSystemsTable(Connection.objects.values('dst_socket__interface__address_inet','dst_socket__port').annotate(dest_ip_counter=Count('dst_socket__interface__address_inet')).order_by('-dest_ip_counter'))


    # D3.js graph
    central_systems_objects = Connection.objects.values(
				'dst_socket__interface__address_inet',
				'dst_socket__port',
                                'src_socket__interface__address_inet')
			#).annotate(
			#	dest_ip_counter=Count('dst_socket__interface__address_inet')
			#).order_by('-dest_ip_counter')

    # prepare chart
    dst_ip = central_systems_objects.values_list('dst_socket__interface__address_inet', flat=True)
    src_ip = central_systems_objects.values_list('src_socket__interface__address_inet', flat=True)
    dst_port = central_systems_objects.values_list('dst_socket__port', flat=True)

    chartdata = {
            'dst': dst_ip, 'src': src_ip, 'port' : dst_port
    }

    RequestConfig(request).configure(table)
    return render(request, 'discovery/queries.html', {
        'table': table,
        #'chartdata': chartdata
	'chartdata' : central_systems_objects
        }
    )

