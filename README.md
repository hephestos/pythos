# Pythos

## Introduction

Pythos is a passive network analysis framework. It intends to understand a presently unknown network architecture by sniffing the network traffic.

The idea for the development originates from the investigation of existing industrial production networks. This is why there are some special considerations
- not all traffic is IP
- link layer communication is well within the scope of investigation
- proprietary protocols are the rule, not the exception
- we are facing a very large variety of operating systems
- networks may be heavily distributed, nested and meshed
- documentation is often sparse and overall documentation of the full network hardly ever available
- several sources of information have to be combined and no single source can be fully trusted
- [...]

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
