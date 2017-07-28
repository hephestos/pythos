import socket

from django import template


register = template.Library()


@register.filter(name='getservbyport')
def getservbyport(value):
    try:
        service = socket.getservbyport(int(value))
    except:
        service = '-'

    return service
