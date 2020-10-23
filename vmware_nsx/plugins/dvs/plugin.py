# Copyright 2012 VMware, Inc.
# All Rights Reserved
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

from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api.definitions import external_net as enet_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import multiprovidernet as mpnet_apidef
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings as pbin
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import allowedaddresspairs as addr_exc
from neutron_lib.exceptions import port_security as psec_exc
from neutron_lib.plugins import utils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils

from neutron.api import extensions as neutron_extensions
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import dns_db
from neutron.db import external_net_db
from neutron.db import l3_db
from neutron.db.models import securitygroup as securitygroup_model  # noqa
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import portsecurity_db
from neutron.db import securitygroups_db
from neutron.db import vlantransparent_db as vlan_ext_db
from neutron.extensions import securitygroup as ext_sg
from neutron.quota import resource_registry


import vmware_nsx
from vmware_nsx._i18n import _
from vmware_nsx.common import config  # noqa
from vmware_nsx.common import managers as nsx_managers
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils as c_utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import nsxv_db
from vmware_nsx.dhcp_meta import modes as dhcpmeta_modes
from vmware_nsx.dvs import dvs
from vmware_nsx.dvs import dvs_utils
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.common import plugin as nsx_plugin_common
from vmware_nsx.plugins.nsx import utils as tvd_utils

LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
class NsxDvsV2(addr_pair_db.AllowedAddressPairsMixin,
               agentschedulers_db.DhcpAgentSchedulerDbMixin,
               nsx_plugin_common.NsxPluginBase,
               dhcpmeta_modes.DhcpMetadataAccess,
               external_net_db.External_net_db_mixin,
               l3_db.L3_NAT_dbonly_mixin,
               portbindings_db.PortBindingMixin,
               portsecurity_db.PortSecurityDbMixin,
               securitygroups_db.SecurityGroupDbMixin,
               dns_db.DNSDbMixin,
               vlan_ext_db.Vlantransparent_db_mixin):

    supported_extension_aliases = [addr_apidef.ALIAS,
                                   pbin.ALIAS,
                                   enet_apidef.ALIAS,
                                   mpnet_apidef.ALIAS,
                                   psec.ALIAS,
                                   pnet.ALIAS,
                                   "quotas",
                                   l3_apidef.ALIAS,
                                   "security-group",
                                   vlan_apidef.ALIAS]

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    @resource_registry.tracked_resources(
        network=models_v2.Network,
        port=models_v2.Port,
        subnet=models_v2.Subnet,
        subnetpool=models_v2.SubnetPool,
        security_group=securitygroup_model.SecurityGroup,
        security_group_rule=securitygroup_model.SecurityGroupRule)
    def __init__(self):
        self._is_sub_plugin = tvd_utils.is_tvd_core_plugin()
        dvs_utils.dvs_register_exceptions()
        super(NsxDvsV2, self).__init__()
        if self._is_sub_plugin:
            extension_drivers = cfg.CONF.nsx_tvd.dvs_extension_drivers
        else:
            extension_drivers = cfg.CONF.nsx_extension_drivers
        self._extension_manager = nsx_managers.ExtensionManager(
             extension_drivers=extension_drivers)
        LOG.debug('Driver support: DVS: %s' % dvs_utils.dvs_is_enabled())
        self._extension_manager.initialize()
        self.supported_extension_aliases.extend(
            self._extension_manager.extension_aliases())
        neutron_extensions.append_api_extensions_path(
            [vmware_nsx.NSX_EXT_PATH])
        self.cfg_group = 'dvs'  # group name for dvs section in nsx.ini
        self._dvs = dvs.SingleDvsManager()
        self.setup_dhcpmeta_access()

    @staticmethod
    def plugin_type():
        return projectpluginmap.NsxPlugins.DVS

    @staticmethod
    def is_tvd_plugin():
        return False

    def plugin_extend_port_dict_binding(self, context, result):
        result[pbin.VIF_TYPE] = nsx_constants.VIF_TYPE_DVS
        if not result['id']:
            return
        db_vnic_type = nsxv_db.get_nsxv_ext_attr_port_vnic_type(
            context.session, result['id'])
        if db_vnic_type:
            result[pbin.VNIC_TYPE] = db_vnic_type
        else:
            result[pbin.VNIC_TYPE] = pbin.VNIC_NORMAL
        result[pbin.VIF_DETAILS] = {
            # TODO(rkukura): Replace with new VIF security details
            # security-groups extension supported by this plugin
            pbin.CAP_PORT_FILTER: True}

    @staticmethod
    def _extend_port_dict_binding(result, portdb):
        result[pbin.VIF_TYPE] = nsx_constants.VIF_TYPE_DVS
        port_attr = portdb.get('nsx_port_attributes')
        if port_attr:
            result[pbin.VNIC_TYPE] = port_attr.vnic_type
        else:
            result[pbin.VNIC_TYPE] = pbin.VNIC_NORMAL
        result[pbin.VIF_DETAILS] = {
            # TODO(rkukura): Replace with new VIF security details
            # security-groups extension supported by this plugin
            pbin.CAP_PORT_FILTER: True}

    def _extend_get_network_dict_provider(self, context, network,
                                          multiprovider=None, bindings=None):
        if not bindings:
            bindings = nsx_db.get_network_bindings(context.session,
                                                   network['id'])
        if not multiprovider:
            multiprovider = nsx_db.is_multiprovider_network(context.session,
                                                            network['id'])
        # With NSX plugin 'normal' overlay networks will have no binding
        # TODO(salvatore-orlando) make sure users can specify a distinct
        # phy_uuid as 'provider network' for STT net type
        if bindings:
            if not multiprovider:
                # network came in through provider networks api
                network[pnet.NETWORK_TYPE] = bindings[0].binding_type
                network[pnet.PHYSICAL_NETWORK] = bindings[0].phy_uuid
                network[pnet.SEGMENTATION_ID] = bindings[0].vlan_id
            else:
                # network come in though multiprovider networks api
                network[mpnet_apidef.SEGMENTS] = [
                    {pnet.NETWORK_TYPE: binding.binding_type,
                     pnet.PHYSICAL_NETWORK: binding.phy_uuid,
                     pnet.SEGMENTATION_ID: binding.vlan_id}
                    for binding in bindings]

    def _dvs_get_id(self, net_data):
        if net_data['name'] == '':
            return net_data['id']
        else:
            # Maximum name length is 80 characters. 'id' length is 36
            # maximum prefix for name is 43
            return '%s-%s' % (net_data['name'][:43], net_data['id'])

    def _add_port_group(self, dvs_id, net_data, vlan_tag, trunk_mode):
        dvs_name = net_data.get(pnet.PHYSICAL_NETWORK,
                                dvs_utils.dvs_name_get())
        self._dvs.add_port_group(dvs_id, dvs_name, vlan_tag,
                                 trunk_mode=trunk_mode)
        return dvs_name

    def _dvs_create_network(self, context, network):
        net_data = network['network']
        if net_data['admin_state_up'] is False:
            LOG.warning("Network with admin_state_up=False are not yet "
                        "supported by this plugin. Ignoring setting for "
                        "network %s", net_data.get('name', '<unknown>'))
        net_data['id'] = uuidutils.generate_uuid()
        vlan_tag = 0
        if net_data.get(pnet.NETWORK_TYPE) == c_utils.NetworkTypes.VLAN:
            vlan_tag = net_data.get(pnet.SEGMENTATION_ID, 0)

        trunk_mode = False
        # vlan transparent can be an object if not set.
        if net_data.get(vlan_apidef.VLANTRANSPARENT) is True:
            trunk_mode = True

        net_id = dvs_name = None
        if net_data.get(pnet.NETWORK_TYPE) == c_utils.NetworkTypes.PORTGROUP:
            net_id = net_data.get(pnet.PHYSICAL_NETWORK)
            pg_info, dvpg_moref = self._dvs.get_port_group_info(net_id)
            if pg_info.get('name') != net_data.get('name'):
                err_msg = (_("Portgroup name %(dvpg)s must match network "
                            "name %(network)s") % {'dvpg': pg_info.get('name'),
                            'network': net_data.get('name')})
                raise n_exc.InvalidInput(error_message=err_msg)
            dvs_id = dvpg_moref.value
        else:
            dvs_id = self._dvs_get_id(net_data)
            try:
                dvs_name = self._add_port_group(dvs_id, net_data, vlan_tag,
                                                trunk_mode=trunk_mode)
            except dvs_utils.DvsOperationBulkFault:
                LOG.warning('One or more hosts may not be configured')

        try:
            with db_api.CONTEXT_WRITER.using(context):
                new_net = super(NsxDvsV2, self).create_network(context,
                                                               network)
                self._extension_manager.process_create_network(
                    context, net_data, new_net)
                # Process port security extension
                self._process_network_port_security_create(
                    context, net_data, new_net)

                # Process vlan transparent extension
                net_db = self._get_network(context, new_net['id'])
                net_db['vlan_transparent'] = trunk_mode
                net_data['vlan_transparent'] = trunk_mode
                resource_extend.apply_funcs('networks', net_data, net_db)

                nsx_db.add_network_binding(
                    context.session, new_net['id'],
                    net_data.get(pnet.NETWORK_TYPE),
                    net_id or dvs_name,
                    vlan_tag)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception('Failed to create network')
                if (net_data.get(pnet.NETWORK_TYPE) !=
                        c_utils.NetworkTypes.PORTGROUP):
                    self._dvs.delete_port_group(dvs_name, dvs_id)

        new_net[pnet.NETWORK_TYPE] = net_data.get(pnet.NETWORK_TYPE)
        new_net[pnet.PHYSICAL_NETWORK] = net_id or dvs_name
        new_net[pnet.SEGMENTATION_ID] = vlan_tag

        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        net_model = self._get_network(context, net_data['id'])
        resource_extend.apply_funcs('networks', new_net, net_model)

        self.handle_network_dhcp_access(context, new_net,
                                        action='create_network')
        return new_net

    def _validate_network(self, context, net_data):
        network_type = net_data.get(pnet.NETWORK_TYPE)
        network_type_set = validators.is_attr_set(network_type)
        segmentation_id = net_data.get(pnet.SEGMENTATION_ID)
        segmentation_id_set = validators.is_attr_set(segmentation_id)
        physical_network = net_data.get(pnet.PHYSICAL_NETWORK)
        physical_network_set = validators.is_attr_set(physical_network)
        if network_type == 'vlan':
            if not physical_network_set:
                physical_network = dvs_utils.dvs_name_get()
            bindings = nsx_db.get_network_bindings_by_vlanid_and_physical_net(
                context.session, segmentation_id, physical_network)
            if bindings:
                err_msg = _("Network with that dvs-id and vlan tag already "
                            "exists")
                raise n_exc.InvalidInput(error_message=err_msg)
        if not context.is_admin:
            err_msg = _("Only an admin can create a DVS provider "
                        "network")
            raise n_exc.InvalidInput(error_message=err_msg)

        external = net_data.get(enet_apidef.EXTERNAL)
        is_external_net = validators.is_attr_set(external) and external
        if is_external_net:
            err_msg = _("External network cannot be created with dvs based "
                        "port groups")
            raise n_exc.InvalidInput(error_message=err_msg)

        err_msg = None
        if not network_type_set:
            err_msg = _("Network provider information must be "
                        "specified")
            raise n_exc.InvalidInput(error_message=err_msg)
        if (network_type == c_utils.NetworkTypes.FLAT or
            network_type == c_utils.NetworkTypes.PORTGROUP):
            if segmentation_id_set:
                err_msg = (_("Segmentation ID cannot be specified with "
                            "%s network type") % network_type)
            if (network_type == c_utils.NetworkTypes.PORTGROUP and
                not physical_network_set):
                err_msg = (_("Physical network must be specified with "
                            "%s network type") % network_type)
        elif network_type == c_utils.NetworkTypes.VLAN:
            if not segmentation_id_set:
                err_msg = _("Segmentation ID must be specified with "
                            "vlan network type")
            if (segmentation_id_set and
                not utils.is_valid_vlan_tag(segmentation_id)):
                err_msg = (_("%(segmentation_id)s out of range "
                             "(%(min_id)s through %(max_id)s)") %
                           {'segmentation_id': segmentation_id,
                            'min_id': constants.MIN_VLAN_TAG,
                            'max_id': constants.MAX_VLAN_TAG})
        else:
            err_msg = (_("%(net_type_param)s %(net_type_value)s not "
                         "supported") %
                       {'net_type_param': pnet.NETWORK_TYPE,
                        'net_type_value': network_type})
        if err_msg:
            raise n_exc.InvalidInput(error_message=err_msg)

    def create_network(self, context, network):
        self._validate_network(context, network['network'])
        return self._dvs_create_network(context, network)

    def _delete_port_group(self, dvs_id, dvs_name):
        self._dvs.delete_port_group(dvs_name, dvs_id)

    def _dvs_delete_network(self, context, id):
        network = self._get_network(context, id)
        dvs_id = self._dvs_get_id(network)
        bindings = nsx_db.get_network_bindings(context.session, id)
        with db_api.CONTEXT_WRITER.using(context):
            nsx_db.delete_network_bindings(context.session, id)
            super(NsxDvsV2, self).delete_network(context, id)
        try:
            if (not bindings or
                bindings[0].binding_type != c_utils.NetworkTypes.PORTGROUP):
                dvs_name = bindings[0].phy_uuid
                self._dvs.delete_port_group(dvs_name, dvs_id)
        except Exception:
            LOG.exception('Unable to delete DVS port group %s', id)
        self.handle_network_dhcp_access(context, id, action='delete_network')

    def delete_network(self, context, id):
        self._dvs_delete_network(context, id)

    def _dvs_get_network(self, context, id, fields=None):
        with db_api.CONTEXT_READER.using(context):
            # goto to the plugin DB and fetch the network
            network = self._get_network(context, id)
            # Don't do field selection here otherwise we won't be able
            # to add provider networks fields
            net_result = self._make_network_dict(network,
                                                 context=context)
            self._extend_get_network_dict_provider(context, net_result)
        return db_utils.resource_fields(net_result, fields)

    def _dvs_get_network_type(self, context, id, fields=None):
        net = self._dvs_get_network(context, id, fields=fields)
        return net[pnet.NETWORK_TYPE]

    def get_network(self, context, id, fields=None):
        return self._dvs_get_network(context, id, fields=None)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        filters = filters or {}
        with db_api.CONTEXT_READER.using(context):
            networks = (
                super(NsxDvsV2, self).get_networks(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            for net in networks:
                self._extend_get_network_dict_provider(context, net)
        return (networks if not fields else
                [db_utils.resource_fields(network,
                                          fields) for network in networks])

    def update_network(self, context, id, network):
        net_attrs = network['network']
        c_utils.raise_if_updates_provider_attributes(net_attrs)

        with db_api.CONTEXT_WRITER.using(context):
            net_res = super(NsxDvsV2, self).update_network(context, id,
                                                           network)
            self._extension_manager.process_update_network(context, net_attrs,
                                                           net_res)
            # Process port security extension
            self._process_network_port_security_update(
                context, net_attrs, net_res)
            self._extend_get_network_dict_provider(context, net_res)

        return net_res

    def _process_vnic_type(self, context, port_data, port_id):
        vnic_type = port_data.get(pbin.VNIC_TYPE)
        if validators.is_attr_set(vnic_type):
            if (vnic_type != pbin.VNIC_NORMAL and
                vnic_type != pbin.VNIC_DIRECT and
                vnic_type != pbin.VNIC_DIRECT_PHYSICAL):
                err_msg = _("Only direct, direct-physical and normal VNIC "
                            "types supported")
                raise n_exc.InvalidInput(error_message=err_msg)
            nsxv_db.update_nsxv_port_ext_attributes(
                session=context.session,
                port_id=port_id,
                vnic_type=vnic_type)

    def create_port(self, context, port):
        # If PORTSECURITY is not the default value ATTR_NOT_SPECIFIED
        # then we pass the port to the policy engine. The reason why we don't
        # pass the value to the policy engine when the port is
        # ATTR_NOT_SPECIFIED is for the case where a port is created on a
        # shared network that is not owned by the tenant.
        port_data = port['port']
        network_type = self._dvs_get_network_type(context, port['port'][
                                                  'network_id'])
        with db_api.CONTEXT_WRITER.using(context):
            # First we allocate port in neutron database
            neutron_db = super(NsxDvsV2, self).create_port(context, port)
            self._extension_manager.process_create_port(
                context, port_data, neutron_db)
            if network_type and network_type == 'vlan':
                # Not allowed to enable port security on vlan DVS ports
                port_data[psec.PORTSECURITY] = False
            else:
                port_security = self._get_network_security_binding(
                    context, neutron_db['network_id'])
                port_data[psec.PORTSECURITY] = port_security
            self._process_port_port_security_create(
                context, port_data, neutron_db)
            # Update fields obtained from neutron db (eg: MAC address)
            port["port"].update(neutron_db)
            has_ip = self._ip_on_port(neutron_db)

            # security group extension checks
            if network_type and network_type != 'vlan':
                if has_ip:
                    self._ensure_default_security_group_on_port(context, port)
                elif validators.is_attr_set(port_data.get(
                        ext_sg.SECURITYGROUPS)):
                    raise psec_exc.PortSecurityAndIPRequiredForSecurityGroups()
            if network_type and network_type == 'vlan':
                port_data[ext_sg.SECURITYGROUPS] = []
            else:
                port_data[ext_sg.SECURITYGROUPS] = (
                    self._get_security_groups_on_port(context, port))
            self._process_port_create_security_group(
                context, port_data, port_data[ext_sg.SECURITYGROUPS])
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         port_data)

            # allowed address pair checks
            if validators.is_attr_set(port_data.get(
                    addr_apidef.ADDRESS_PAIRS)):
                if not port_security:
                    raise addr_exc.AddressPairAndPortSecurityRequired()
                else:
                    self._process_create_allowed_address_pairs(
                        context, neutron_db,
                        port_data[addr_apidef.ADDRESS_PAIRS])
            else:
                # remove ATTR_NOT_SPECIFIED
                port_data[addr_apidef.ADDRESS_PAIRS] = []

            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         port_data)
            self._process_vnic_type(context, port_data, neutron_db['id'])

            LOG.debug("create_port completed on NSX for tenant "
                      "%(tenant_id)s: (%(id)s)", port_data)

        # DB Operation is complete, perform DVS operation
        port_data = port['port']

        self.plugin_extend_port_dict_binding(context, port_data)
        self.handle_port_dhcp_access(context, port_data, action='create_port')
        return port_data

    def update_port(self, context, id, port):
        delete_addr_pairs = self._check_update_deletes_allowed_address_pairs(
            port)
        has_addr_pairs = self._check_update_has_allowed_address_pairs(port)
        with db_api.CONTEXT_WRITER.using(context):
            ret_port = super(NsxDvsV2, self).update_port(
                context, id, port)
            # Save current mac learning state to check whether it's
            # being updated or not
            # copy values over - except fixed_ips as
            # they've already been processed
            port['port'].pop('fixed_ips', None)
            ret_port.update(port['port'])

            # populate port_security setting, ignoring vlan network ports.
            network_type = self._dvs_get_network_type(context,
                                                      ret_port['network_id'])
            if (psec.PORTSECURITY not in port['port'] and network_type !=
                    'vlan'):
                ret_port[psec.PORTSECURITY] = self._get_port_security_binding(
                    context, id)
            elif (network_type == 'vlan' and
                  psec.PORTSECURITY in port['port'] and
                  port['port'][psec.PORTSECURITY]):
                # Not allowed to enable port security on vlan DVS ports
                err_msg = _("Cannot enable port security on port %s") % id
                raise n_exc.InvalidInput(error_message=err_msg)

            # validate port security and allowed address pairs
            if not ret_port[psec.PORTSECURITY]:
                #  has address pairs in request
                if has_addr_pairs:
                    raise addr_exc.AddressPairAndPortSecurityRequired()
                elif not delete_addr_pairs:
                    # check if address pairs are in db
                    ret_port[addr_apidef.ADDRESS_PAIRS] = (
                        self.get_allowed_address_pairs(context, id))
                    if ret_port[addr_apidef.ADDRESS_PAIRS]:
                        raise addr_exc.AddressPairAndPortSecurityRequired()

            if delete_addr_pairs or has_addr_pairs:
                # delete address pairs and read them in
                self._delete_allowed_address_pairs(context, id)
                self._process_create_allowed_address_pairs(
                    context, ret_port, ret_port[addr_apidef.ADDRESS_PAIRS])

            if psec.PORTSECURITY in port['port']:
                if network_type != 'vlan':
                    self._process_port_port_security_update(
                        context, port['port'], ret_port)
                else:
                    ret_port[psec.PORTSECURITY] = False
            self._process_vnic_type(context, port['port'], id)
            LOG.debug("Updating port: %s", port)
            self._extension_manager.process_update_port(
                context, port['port'], ret_port)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         ret_port)
        return ret_port

    def delete_port(self, context, id, l3_port_check=True,
                    nw_gw_port_check=True):
        """Deletes a port on a specified Virtual Network.

        If the port contains a remote interface attachment, the remote
        interface is first un-plugged and then the port is deleted.

        :returns: None
        :raises: exception.PortInUse
        :raises: exception.PortNotFound
        :raises: exception.NetworkNotFound
        """
        neutron_db_port = self.get_port(context, id)

        with db_api.CONTEXT_WRITER.using(context):
            # metadata_dhcp_host_route
            self.handle_port_metadata_access(
                context, neutron_db_port, is_delete=True)
            super(NsxDvsV2, self).delete_port(context, id)
        self.handle_port_dhcp_access(
            context, neutron_db_port, action='delete_port')

    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        filters = filters or {}
        with db_api.CONTEXT_READER.using(context):
            ports = (
                super(NsxDvsV2, self).get_ports(
                      context, filters, fields, sorts,
                      limit, marker, page_reverse))
            self._log_get_ports(ports, filters)
            # Add port extensions
            for port in ports:
                self.plugin_extend_port_dict_binding(context, port)
        return (ports if not fields else
                [db_utils.resource_fields(port, fields) for port in ports])

    def get_port(self, context, id, fields=None):
        port = super(NsxDvsV2, self).get_port(context, id, fields=None)
        self.plugin_extend_port_dict_binding(context, port)
        return db_utils.resource_fields(port, fields)

    def create_router(self, context, router):
        # DVS backend cannot support logical router
        msg = (_("Unable to create router %s with DVS") %
               router['router']['name'])
        raise n_exc.BadRequest(resource="router", msg=msg)

    def get_network_availability_zones(self, net_db):
        """Api to comply with the NSX-TVD plugin"""
        return []
