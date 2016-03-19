from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.template import RequestContext, loader
from django.views import generic

import netifaces

from .models import Interface

class IndexView(generic.ListView):
        template_name = 'discovery/index.html'
        context_object_name = 'hosts_list'

        def get_queryset(self):
                return Host.objects.order_by('address_inet4')

def FormInterfaces(request):
        if request.method == 'POST':
                try:
                        iface_list = netifaces.interfaces()
                except:
                        return
                Interface.objects.all().delete()
                for iface in iface_list:
                        try:
                                addrs = netifaces.ifaddresses(iface)
                        except:
                                addrs = 0
                        new_iface = Interface(name=iface, address_ether=addrs[netifaces.AF_LINK])
                        new_iface.save()
        else:
                # Print Form

def sites(request):
        return render(request, 'config/sites.html')
