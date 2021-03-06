#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from oslo_policy import policy

from vmware_nsx.policies import base


rules = [
    policy.RuleDefault(
        'create_qos_queue',
        base.RULE_ADMIN_ONLY,
        description='Create a QoS queue'),
    policy.RuleDefault(
        'get_qos_queue',
        base.RULE_ADMIN_ONLY,
        description='Get QoS queues'),

    policy.DocumentedRuleDefault(
        'get_network:queue_id',
        base.RULE_ADMIN_ONLY,
        'Get ``queue_id`` attributes of networks',
        [
            {
                'method': 'GET',
                'path': '/networks',
            },
            {
                'method': 'GET',
                'path': '/networks/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_port:queue_id',
        base.RULE_ADMIN_ONLY,
        'Get ``queue_id`` attributes of ports',
        [
            {
                'method': 'GET',
                'path': '/ports',
            },
            {
                'method': 'GET',
                'path': '/ports/{id}',
            },
        ]
    ),
]


def list_rules():
    return rules
