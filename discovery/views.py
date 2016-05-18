from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.template import RequestContext, loader
from django.views import generic
from macaddress import format_mac

import netifaces
import pyshark

from .models import Interface
from .forms import ControlForm, PcapForm
from .tasks import DiscoveryTask, PcapTask

class IndexView(generic.ListView):
        template_name = 'discovery/index.html'
        context_object_name = 'interface_list'

        def get_queryset(self):
                return Interface.objects.order_by('address_inet')

def ControlView(request):
        if request.method == 'POST':
                form = ControlForm(request.POST)
                if form.is_valid():
                        capture_interface = form.cleaned_data['interface']
                        capture_duration = form.cleaned_data['duration']

                        DiscoveryTask.delay(capture_interface, capture_duration)

                        return render(request, 'discovery/control.html', {'form': form})
        else:
                form = ControlForm()

        return render(request, 'discovery/control.html', {'form': form})

def PcapView(request):
        if request.method == 'POST':
                form = PcapForm(request.POST)
                if form.is_valid():
                        filepath = form.cleaned_data['filepath']
                        origin_description = form.cleaned_data['origin_description']

                        PcapTask.delay(filepath, origin_description)

                        return render(request, 'discovery/pcap.html', {'form': form})
        else:
                form = PcapForm()

        return render(request, 'discovery/pcap.html', {'form': form})
