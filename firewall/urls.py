from django.conf.urls import url

from . import views


urlpatterns = [
    # ex: /firewall/
#    url(r'^$', views.index, name='index'),
    # ex: /firewall/1/
#    url(r'^(?P<firewall_id>[0-9]+)/$', views.firewall, name='firewall'),
    # ex: /firewall/1/2/
    url(r'^(?P<firewall_id>[0-9]+)/(?P<ruleset_id>[0-9]+)/$', views.ruleset, name='ruleset'),
    # ex: /firewall/1/2/3/
    url(r'^(?P<firewall_id>[0-9]+)/(?P<ruleset_id>[0-9]+)/(?P<rule_id>[0-9]+)/$', views.rule, name='rule'),
    # ex: /firewall/1/2/3/4/
#    url(r'^(?P<firewall_id>[0-9]+)/(?P<ruleset_id>[0-9]+)/(?P<rule_id>[0-9]+)/(?P<hit_id>[0-9]+)/$', views.hit, name='hit'),
]
