# Reference:
# https://puppet.com/docs/puppet/8/create_types_and_providers_resource_api.html

# At a minimum, when declaring a rule to be enforced by Puppet, you must specify:
# - name
# - local_port
# - protocol
#
# It will be assumed if the rule is defined in the catalogue then it should be:
# - Enabled (cannot be overridden; this provider only ever concerns itself with rules that are Enabled in Windows Firewall)
# - Allow the traffic (can be set to Block)
# - and is an Inbound rule (can be set to Outbound)
#
# When a Purge/Delete is done by Puppet, the firewall rule is set to DISABLED in Windows Firewall. It is NOT deleted from the system.
# This is by design.

require 'puppet/resource_api'

Puppet::ResourceApi.register_type(
    name: 'winfwrule',
    desc: <<-EOS,
        This type provides Puppet with the capabilities to manage Windows Firewall Rules.
    EOS
    features: ['canonicalize'],
    attributes: {
        ensure: {
            type:       'Enum[present, absent]',
            desc:       'Whether this firewall rule should be present or absent on the target system.',
            default:    'present',
        },
        name: {
            type:       'String',
            desc:       'The unique instance ID of this firewall rule.',
            behaviour:  :namevar,
        },
        action: {
            type:       'Enum["Block","Allow","NotConfigured"]',
            desc:       'The action this firewall rule should take.',
            default:    'Allow'
        },
        direction: {
            type:       'Enum["Inbound","Outbound"]',
            desc:       'The direction of traffic this firewall rule manages.',
            default:    'Inbound',
        },
        description: {
            type:       'Optional[String]',
            desc:       'A description of this firewall rule.',
        },
        display_name: {
            type:       'Optional[String]',
            desc:       'The display name of this firewall rule.', 
        },
        firewall_profile: {
            type:       'Variant[Enum["Any","Domain","Private","Public","NotApplicable"], Array[Enum["Any","Domain","Private","Public","NotApplicable"]]]',
            desc:       'The profile this firewall rule applies to.',
            default:    ['Domain', 'Private', 'Public'],
        },
        icmp_type: {
            type:       'Array[String]',
            desc:       'The ICMP type this firewall rule affects.',
            default:    ['Any'],
        },
        local_address: {
            type:       'Variant[String, Stdlib::IP::Address, Stdlib::IP::Address::V6::Compressed, Array[Variant[Stdlib::IP::Address, Stdlib::IP::Address::V6::Compressed, String]]]',
            desc:       'The local address this firewall rule affects.',
            default:    ['Any'],
        },
        local_port: {
            type:       'Variant[String, Stdlib::Port, Array[Variant[Stdlib::Port, String]], Pattern[/\A[1-9]{1}\Z|[1-9]{1}[0-9,-]*[0-9]{1}\Z/]]',
            desc:       'The local port this firewall rule manages.',
        },
        package: {
            type:       'Optional[String]',
            desc:       'The package this firewall rule affects.',
        },
        program: {
            type:       'String',
            desc:       'The program this firewall rule affects.',
            default:    'Any',
        },
        protocol: {
            type:       'String',
            desc:       'The protocol this firewall rule affects.',
        },
        remote_address: {
            type:       'Variant[String, Stdlib::IP::Address, Stdlib::IP::Address::V6::Compressed, Array[Variant[Stdlib::IP::Address, Stdlib::IP::Address::V6::Compressed, String]]]',
            desc:       'The remote address this firewall rule affects.',
            default:    ['Any'],
        },
        remote_port: {
            type:       'Variant[String, Stdlib::Port, Array[Variant[Stdlib::Port, String]], Pattern[/\A[1-9]{1}\Z|[1-9]{1}[0-9,-]*[0-9]{1}\Z/]]',
            desc:       'The remote port this firewall rule affects.',
            default:    ['Any'],
        },
        service: {
            type:       'String',
            desc:       'The service this firewall rule affects.',
            default:    'Any',
        },
    },
)