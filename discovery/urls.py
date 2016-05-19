from django.conf.urls import url

from . import views

urlpatterns = [
        url(r'^$', views.IndexView.as_view(), name='index'),
        url(r'^control/$', views.ControlView, name='control'),
        url(r'^pcap/$', views.PcapView, name='pcap'),
        url(r'^endpoints/$', views.EndpointsView, name='endpoints'),
        url(r'^conversations/$', views.ConversationsView, name='conversations'),
]
