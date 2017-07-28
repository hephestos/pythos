from django.conf.urls import url

from . import views


urlpatterns = [
    # ex: /netflow/
#    url(r'^$', views.index, name='index'),
    # ex: /netflow/1/
    url(r'^(?P<min_flow_count>[0-9]+)/$', views.flows, name='flows'),
    # ex: /netflow/singlerow/1/
    url(r'^singlerow/(?P<min_flow_count>[0-9]+)/$', views.flows_single, name='flows_singlerow'),
]
