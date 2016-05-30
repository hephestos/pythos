# Pythos

## Introduction

Pythos is a passive network analysis framework. It intends to understand a presently unknown network architecture by sniffing the network traffic.

Pythos is currently under heavy development.

In future releases the following functionality will be available:

Pythos is analyzing the network traffic to identify
- communication relations
- offered network services (for each system)
- used network services (for each system)
- roles and functions of systems by using templates (e.g. print server)
- gateway detection
- [...]

The aggregated information results in network diagrams for a network architecture overview.

## Usage
Celery has to be started with the following command line from the pythos project folder:
C_FORCE_ROOT=true celery -A pythos worker -l info -c 5
