# Copyright 2014 VMware, Inc.
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

from oslo_config import cfg
from oslo_vmware import api
from oslo_vmware import exceptions as oslo_vmware_exc

from vmware_nsx._i18n import _

dvs_opts = [
    cfg.StrOpt('host_ip',
               help='Hostname or IP address for connection to VMware vCenter '
                    'host.'),
    cfg.PortOpt('host_port', default=443,
                help='Port for connection to VMware vCenter host.'),
    cfg.StrOpt('host_username',
               help='Username for connection to VMware vCenter host.'),
    cfg.StrOpt('host_password',
               help='Password for connection to VMware vCenter host.',
               secret=True),
    cfg.FloatOpt('task_poll_interval',
                 default=0.5,
                 help='The interval used for polling of remote tasks.'),
    cfg.StrOpt('ca_file',
               help='Specify a CA bundle file to use in verifying the '
                    'vCenter server certificate.'),
    cfg.BoolOpt('insecure',
                default=False,
                help='If true, the vCenter server certificate is not '
                     'verified. If false, then the default CA truststore is '
                     'used for verification. This option is ignored if '
                     '"ca_file" is set.'),
    cfg.IntOpt('api_retry_count',
               default=10,
               help='The number of times we retry on failures, e.g., '
                    'socket error, etc.'),
    cfg.StrOpt('dvs_name',
               help='The name of the preconfigured DVS.'),
    cfg.StrOpt('metadata_mode',
               help=_("This value should not be set. It is just required for "
                      "ensuring that the DVS plugin works with the generic "
                      "NSX metadata code")),
]

multi_dvs = cfg.ListOpt('enabled_dvs', default=[],
                        help='Optional parameter for defining multiple '
                               'vcenters to connect to. The configuration of'
                               'each vcenter will be under a group names'
                               '[dvs:<name>]')

CONF = cfg.CONF
CONF.register_opts([*dvs_opts, multi_dvs], 'dvs')


def _register_dvs(conf, dvs, opts):
    """
    Register options for all declared vcenters

    :param conf: plugin configuration
    :param dvs: list of vcenters
    :param opts: configuration options for each vcenter
    """
    for vcenter in dvs:
        vcenter_group = f'dvs:{vcenter}'
        conf.register_group(cfg.OptGroup(
            name=vcenter_group,
            title=f"Configuration for dvs {dvs}"))
        conf.register_opts(opts, group=vcenter_group)


_register_dvs(CONF, CONF.dvs.enabled_dvs, dvs_opts)


# Create and register exceptions not in oslo.vmware
class DvsOperationBulkFault(oslo_vmware_exc.VimException):
    msg_fmt = _("Cannot complete a DVS operation for one or more members.")


def dvs_register_exceptions():
    oslo_vmware_exc.register_fault_class('DvsOperationBulkFault',
                                         DvsOperationBulkFault)


def dvs_is_enabled(dvs_id=None):
    """Returns the configured DVS status."""
    return bool(CONF.dvs.host_ip and CONF.dvs.host_username and
                CONF.dvs.host_password and (dvs_id or CONF.dvs.dvs_name))


def dvs_create_session(vcenter=None):
    """
    Create session for vcenter
    If no vcenter is specified, load default one

    :param vcenter: vcenter name
    """
    conf = getattr(CONF, f"dvs{':' + vcenter if vcenter is not None else ''}")
    return api.VMwareAPISession(conf.host_ip,
                                conf.host_username,
                                conf.host_password,
                                conf.api_retry_count,
                                conf.task_poll_interval,
                                port=conf.host_port,
                                cacert=conf.ca_file,
                                insecure=conf.insecure)


def dvs_name_get():
    return CONF.dvs.dvs_name


def dvs_vcenters_get():
    """
    Return configuration name for all vcenters
    """
    return CONF.dvs.enabled_dvs or [None]
