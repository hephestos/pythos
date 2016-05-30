from django.conf.urls import url

from . import views

urlpatterns = [
        # Overview of identified systems
        url(r'^$', views.IndexView.as_view(), name='index'),
        # Discovery control interface (trigger to capture traffic on specific interfaces)
        url(r'^control/$', views.ControlView, name='control'),
        # Process PCAP files from predefined folder for analysis
        url(r'^pcap/$', views.PcapView, name='pcap'),
        # Overview of identified systems as table (same as IndexView)
        url(r'^endpoints/$', views.EndpointsView, name='endpoints'),
        # Overview of identified conversations (per ip addresses and used ports in both directions)
        url(r'^conversations/$', views.ConversationsView, name='conversations'),
]
