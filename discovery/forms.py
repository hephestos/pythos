from django import forms

import netifaces

class ControlForm(forms.Form):
        INTERFACE_CHOICES = [(iface,iface) for iface in netifaces.interfaces()]

        DURATION_CHOICES = [
                ('5',  '5 seconds'),
                ('30', '30 seconds'),
                ('60', '1 minute'),
                ('300', '5 minutes'),
                ('900', '15 minutes'),
                ('3600', '1 hour'),
                ('14400', '4 hours'),
                ('28800', '8 hours'),
                ('86400', '1 day'),
                ('604800', '1 week'),
        ]

        interface = forms.ChoiceField(label='Select interface',
                                      choices=INTERFACE_CHOICES,
                                      widget=forms.Select,
                                      required=True)

        duration  = forms.ChoiceField(label='Choose duration',
                                      choices=DURATION_CHOICES,
                                      widget=forms.Select,
                                      required=True)

