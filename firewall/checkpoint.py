# import python modules
import logging
import os
import csv
from datetime import datetime

# import django modules
from django.utils import timezone
from django.utils.timezone import make_aware, utc
from django.db.models import Count
from django.db import IntegrityError

# import third party modules
from profilehooks import profile

# import project specific model classes
from .models import Firewall, RuleSet, Rule, Log, Hit
from architecture.models import NetObject
from kb.models import ServiceName
from kb.models import OperatingSystem


def checkpoint_read_log_csv(filename):
    HEADERS = set(["Number", "Date", "Time", "Interface", "Origin", "Type",
                   "Action", "Service", "Source Port", "Source", "Destination",
                   "Protocol", "Rule", "Rule Name", "Current Rule Number",
                   "User", "Information", "Product", "Source Machine Name",
                   "Source User Name"])

    with open(filename, newline='') as csvfile:
        logreader = csv.DictReader(csvfile, delimiter=' ', quotechar='"')
        if logreader:
            log = Log.objects.create(
                    src_file=filename,
                  )

        if not HEADERS.issubset(set(logreader.fieldnames)):
            raise RuntimeError("The input file does not appear to be a \
                                CheckPoint log file. Quitting.")

        for row in logreader:
            if row['Type'] != 'Log':
                continue

            firewall, new_firewall = Firewall.objects.get_or_create(
                                        name=row['Origin']
                                     )

            ruleset, new_ruleset = RuleSet.objects.get_or_create(
                                        firewall=firewall,
                                        description='Derived from logs',
                                   )

            src, new_src = NetObject.objects.get_or_create(
                                name=row['Source'],
                           )

            dst, new_dst = NetObject.objects.get_or_create(
                                name=row['Destination'],
                           )

            src_service, new_src_service = ServiceName.objects.get_or_create(
                                                protocol_l3=row['Protocol'],
                                                port=row['Source Port'],
                                           )

            dst_service, new_dst_service = ServiceName.objects.get_or_create(
                                                protocol_l3=row['Protocol'],
                                                port=row['Service'],
                                           )

            rule, new_rule = Rule.objects.get_or_create(
                                ruleset=ruleset,
                                name=row['Rule Name'],
                                number=int('0'+row['Rule']),
                                action=row['Action'],
                             )

            if dst_service not in rule.services.all():
                rule.services.add(dst_service) 

            if src not in rule.srcs.all():
                rule.srcs.add(src)

            if dst not in rule.dsts.all():
                rule.dsts.add(dst)

            hit = Hit.objects.create(
                    log=log,
                    rule=rule,
                    src=src,
                    src_service=src_service,
                    dst=dst,
                    dst_service=dst_service,
                    hit_time=make_aware(datetime.strptime(row['Date'] +
                                                          row['Time'], "%d%b%Y%H:%M:%S"), utc),
                    interface=row['Interface'],
                    user=row['User'],
                    src_machine_name=row['Source Machine Name'],
                    src_user_name=row['Source User Name'],
                  )
