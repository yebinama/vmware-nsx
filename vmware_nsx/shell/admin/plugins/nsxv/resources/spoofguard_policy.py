# Copyright 2015 VMware, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import logging


from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters

import vmware_nsx.shell.admin.plugins.common.utils as admin_utils
import vmware_nsx.shell.admin.plugins.nsxv.resources.utils as utils
import vmware_nsx.shell.nsxadmin as shell

from neutron.callbacks import registry

from vmware_nsx._i18n import _LI
from vmware_nsx.db import nsxv_db

LOG = logging.getLogger(__name__)


def get_spoofguard_policies():
    nsxv = utils.get_nsxv_client()
    return nsxv.get_spoofguard_policies()[1].get("policies")


@admin_utils.output_header
def nsx_list_spoofguard_policies(resource, event, trigger, **kwargs):
    """List spoofguard policies from NSXv backend"""
    policies = get_spoofguard_policies()
    LOG.info(formatters.output_formatter(constants.SPOOFGUARD_POLICY, policies,
                                         ['policyId', 'name']))


def get_spoofguard_policy_network_mappings():
    spgapi = utils.NeutronDbClient()
    return nsxv_db.get_nsxv_spoofguard_policy_network_mappings(
        spgapi.context)


@admin_utils.output_header
def neutron_list_spoofguard_policy_mappings(resource, event, trigger,
                                            **kwargs):
    mappings = get_spoofguard_policy_network_mappings()
    LOG.info(formatters.output_formatter(constants.SPOOFGUARD_POLICY, mappings,
                                         ['network_id', 'policy_id']))


def get_missing_spoofguard_policy_mappings():
    nsxv_spoofguard_policies = set()
    for spg in get_spoofguard_policies():
        nsxv_spoofguard_policies.add(spg.get('policyId'))

    neutron_spoofguard_policy_mappings = set()
    for binding in get_spoofguard_policy_network_mappings():
        neutron_spoofguard_policy_mappings.add(binding.policy_id)

    return neutron_spoofguard_policy_mappings - nsxv_spoofguard_policies


@admin_utils.output_header
def nsx_list_missing_spoofguard_policies(resource, event, trigger,
                                         **kwargs):
    """List missing spoofguard policies on NSXv.

    Spoofguard policies that have a binding in Neutron Db but there is
    no policy on NSXv backend to back it.
    """
    LOG.info(_LI("Spoofguard policies in Neutron Db but not present on NSXv"))
    missing_policies = get_missing_spoofguard_policy_mappings()
    if not missing_policies:
        LOG.info(_LI("\nNo missing spoofguard policies found."
                     "\nNeutron DB and NSXv backend are in sync\n"))
    else:
        LOG.info(formatters.output_formatter(
            constants.SPOOFGUARD_POLICY, missing_policies, ['policy_id']))


registry.subscribe(neutron_list_spoofguard_policy_mappings,
                   constants.SPOOFGUARD_POLICY,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_list_spoofguard_policies,
                   constants.SPOOFGUARD_POLICY,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_list_missing_spoofguard_policies,
                   constants.SPOOFGUARD_POLICY,
                   shell.Operations.LIST.value)