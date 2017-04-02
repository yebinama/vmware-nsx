# Copyright 2017 VMware, Inc.
#
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

from oslo_log import log as logging

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron_dynamic_routing.db import bgp_db
from neutron_dynamic_routing.extensions import bgp as bgp_ext
from neutron_lib import context as n_context
from neutron_lib.services import base as service_base

from vmware_nsx.common import locking
from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import nsxv_db
from vmware_nsx.extensions import edge_service_gateway_bgp_peer as ext_esg
from vmware_nsx.services.dynamic_routing.nsx_v import driver as nsxv_driver

PLUGIN_NAME = bgp_ext.BGP_EXT_ALIAS + '_nsx_svc_plugin'
LOG = logging.getLogger(__name__)


class NSXvBgpPlugin(service_base.ServicePluginBase, bgp_db.BgpDbMixin):

    supported_extension_aliases = [bgp_ext.BGP_EXT_ALIAS,
                                   ext_esg.ESG_BGP_PEER_EXT_ALIAS]

    def __init__(self):
        super(NSXvBgpPlugin, self).__init__()
        self.nsxv_driver = nsxv_driver.NSXvBgpDriver(self)
        self._register_callbacks()

    def get_plugin_name(self):
        return PLUGIN_NAME

    def get_plugin_type(self):
        return bgp_ext.BGP_EXT_ALIAS

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("BGP dynamic routing service for announcement of next-hops "
                "for project networks, floating IP's, and DVR host routes.")

    def _register_callbacks(self):
        registry.subscribe(self.router_interface_callback,
                           resources.ROUTER_INTERFACE,
                           events.AFTER_CREATE)
        registry.subscribe(self.router_interface_callback,
                           resources.ROUTER_INTERFACE,
                           events.AFTER_DELETE)
        registry.subscribe(self.router_gateway_callback,
                           resources.ROUTER_GATEWAY,
                           events.AFTER_CREATE)
        registry.subscribe(self.router_gateway_callback,
                           resources.ROUTER_GATEWAY,
                           events.AFTER_DELETE)
        registry.subscribe(self._after_service_edge_create_callback,
                           nsxv_constants.SERVICE_EDGE,
                           events.AFTER_CREATE)
        registry.subscribe(self._before_service_edge_delete_callback,
                           nsxv_constants.SERVICE_EDGE,
                           events.BEFORE_DELETE)

    def create_bgp_speaker(self, context, bgp_speaker):
        self.nsxv_driver.create_bgp_speaker(context, bgp_speaker)
        return super(NSXvBgpPlugin, self).create_bgp_speaker(context,
                                                             bgp_speaker)

    def update_bgp_speaker(self, context, bgp_speaker_id, bgp_speaker):
        with locking.LockManager.get_lock(str(bgp_speaker_id)):
            self.nsxv_driver.update_bgp_speaker(context, bgp_speaker_id,
                                               bgp_speaker)
            # TBD(roeyc): rolling back changes on edges base class call failed.
            return super(NSXvBgpPlugin, self).update_bgp_speaker(
                context, bgp_speaker_id, bgp_speaker)

    def delete_bgp_speaker(self, context, bgp_speaker_id):
        with locking.LockManager.get_lock(str(bgp_speaker_id)):
            self.nsxv_driver.delete_bgp_speaker(context, bgp_speaker_id)
            super(NSXvBgpPlugin, self).delete_bgp_speaker(context,
                                                          bgp_speaker_id)

    def _get_esg_peer_info(self, context, bgp_peer_id):
        binding = nsxv_db.get_nsxv_bgp_peer_edge_binding(context.session,
                                                         bgp_peer_id)
        if binding:
            return binding['edge_id']

    def get_bgp_peer(self, context, bgp_peer_id, fields=None):
        peer = super(NSXvBgpPlugin, self).get_bgp_peer(context,
                                                       bgp_peer_id, fields)
        if fields is None or 'esg_id' in fields:
            peer['esg_id'] = self._get_esg_peer_info(context, bgp_peer_id)
        return peer

    def get_bgp_peers_by_bgp_speaker(self, context,
                                     bgp_speaker_id, fields=None):
        ret = super(NSXvBgpPlugin, self).get_bgp_peers_by_bgp_speaker(
            context, bgp_speaker_id, fields=fields)
        if fields is None or 'esg_id' in fields:
            for peer in ret:
                peer['esg_id'] = self._get_esg_peer_info(context, peer['id'])
        return ret

    def create_bgp_peer(self, context, bgp_peer):
        self.nsxv_driver.create_bgp_peer(context, bgp_peer)
        peer = super(NSXvBgpPlugin, self).create_bgp_peer(context, bgp_peer)
        esg_id = bgp_peer['bgp_peer'].get('esg_id')
        if esg_id:
            nsxv_db.add_nsxv_bgp_peer_edge_binding(context.session, peer['id'],
                                                   esg_id)
            peer['esg_id'] = esg_id
        return peer

    def update_bgp_peer(self, context, bgp_peer_id, bgp_peer):
        super(NSXvBgpPlugin, self).update_bgp_peer(context,
                                                   bgp_peer_id, bgp_peer)
        self.nsxv_driver.update_bgp_peer(context, bgp_peer_id, bgp_peer)
        return self.get_bgp_peer(context, bgp_peer_id)

    def delete_bgp_peer(self, context, bgp_peer_id):
        bgp_peer_info = {'bgp_peer_id': bgp_peer_id}
        bgp_speaker_ids = self.nsxv_driver._get_bgp_speakers_by_bgp_peer(
            context, bgp_peer_id)
        for speaker_id in bgp_speaker_ids:
            self.remove_bgp_peer(context, speaker_id, bgp_peer_info)
        super(NSXvBgpPlugin, self).delete_bgp_peer(context, bgp_peer_id)

    def add_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        with locking.LockManager.get_lock(str(bgp_speaker_id)):
            self.nsxv_driver.add_bgp_peer(context,
                                         bgp_speaker_id, bgp_peer_info)
            return super(NSXvBgpPlugin, self).add_bgp_peer(context,
                                                           bgp_speaker_id,
                                                           bgp_peer_info)

    def remove_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        with locking.LockManager.get_lock(str(bgp_speaker_id)):
            speaker = self._get_bgp_speaker(context, bgp_speaker_id)
            if bgp_peer_info['bgp_peer_id'] not in speaker['peers']:
                return
            self.nsxv_driver.remove_bgp_peer(context,
                                            bgp_speaker_id, bgp_peer_info)
            return super(NSXvBgpPlugin, self).remove_bgp_peer(
                context, bgp_speaker_id, bgp_peer_info)

    def add_gateway_network(self, context, bgp_speaker_id, network_info):
        with locking.LockManager.get_lock(str(bgp_speaker_id)):
            self.nsxv_driver.add_gateway_network(context,
                                                bgp_speaker_id,
                                                network_info)
            return super(NSXvBgpPlugin, self).add_gateway_network(
                context, bgp_speaker_id, network_info)

    def remove_gateway_network(self, context, bgp_speaker_id, network_info):
        with locking.LockManager.get_lock(str(bgp_speaker_id)):
            super(NSXvBgpPlugin, self).remove_gateway_network(
                context, bgp_speaker_id, network_info)
            self.nsxv_driver.remove_gateway_network(context,
                                                   bgp_speaker_id,
                                                   network_info)

    def get_advertised_routes(self, context, bgp_speaker_id):
        return super(NSXvBgpPlugin, self).get_advertised_routes(
            context, bgp_speaker_id)

    def router_interface_callback(self, resource, event, trigger, **kwargs):
        if not kwargs['network_id']:
            # No GW network, hence no BGP speaker associated
            return

        context = kwargs['context']
        router_id = kwargs['router_id']
        subnets = kwargs.get('subnets')
        network_id = kwargs['network_id']
        port = kwargs['port']

        speakers = self._bgp_speakers_for_gateway_network(context,
                                                          network_id)
        for speaker in speakers:
            speaker_id = speaker.id
            with locking.LockManager.get_lock(str(speaker_id)):
                speaker = self.get_bgp_speaker(context, speaker_id)
                if network_id not in speaker['networks']:
                    continue
                if event == events.AFTER_CREATE:
                    self.nsxv_driver.advertise_subnet(context, speaker_id,
                                                     router_id, subnets[0])
                if event == events.AFTER_DELETE:
                    subnet_id = port['fixed_ips'][0]['subnet_id']
                    self.nsxv_driver.withdraw_subnet(context, speaker_id,
                                                    router_id, subnet_id)

    def router_gateway_callback(self, resource, event, trigger, **kwargs):
        context = kwargs.get('context') or n_context.get_admin_context()
        router_id = kwargs['router_id']
        network_id = kwargs['network_id']
        speakers = self._bgp_speakers_for_gateway_network(context, network_id)

        for speaker in speakers:
            speaker_id = speaker.id
            with locking.LockManager.get_lock(str(speaker_id)):
                speaker = self.get_bgp_speaker(context, speaker_id)
                if network_id not in speaker['networks']:
                    continue
                if event == events.AFTER_DELETE:
                    gw_ips = kwargs['gateway_ips']
                    self.nsxv_driver.disable_bgp_on_router(context,
                                                          speaker,
                                                          router_id,
                                                          gw_ips[0])

    def _before_service_edge_delete_callback(self, resource, event,
                                             trigger, **kwargs):
        context = kwargs['context']
        router = kwargs['router']
        ext_net_id = router.gw_port and router.gw_port['network_id']
        gw_ip = router.gw_port and router.gw_port['fixed_ips'][0]['ip_address']
        edge_id = kwargs.get('edge_id')
        speakers = self._bgp_speakers_for_gateway_network(context, ext_net_id)
        for speaker in speakers:
            with locking.LockManager.get_lock(speaker.id):
                speaker = self.get_bgp_speaker(context, speaker.id)
                if ext_net_id not in speaker['networks']:
                    continue
                self.nsxv_driver.disable_bgp_on_router(context, speaker,
                                                       router['id'],
                                                       gw_ip, edge_id)

    def _after_service_edge_create_callback(self, resource, event,
                                            trigger, **kwargs):
        context = kwargs['context']
        router = kwargs['router']
        ext_net_id = router.gw_port and router.gw_port['network_id']
        speakers = self._bgp_speakers_for_gateway_network(context, ext_net_id)
        for speaker in speakers:
            with locking.LockManager.get_lock(speaker.id):
                speaker = self.get_bgp_speaker(context, speaker.id)
                if ext_net_id not in speaker['networks']:
                    continue
                self.nsxv_driver.enable_bgp_on_router(context, speaker,
                                                      router['id'])