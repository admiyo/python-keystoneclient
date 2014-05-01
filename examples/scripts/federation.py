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

import os

from keystoneclient import client
from keystoneclient import exceptions
from keystoneclient import session
from keystoneclient.auth.identity import v3


def display(keystone_client, stage):
    print(stage)

    for mapping in keystone_client.federation.mappings.list():
        print(mapping.rules)
    for provider in keystone_client.federation.identity_providers.list():
        print("provider = %s" % provider.id)
        for protocol in keystone_client.federation.protocols.list(provider):
            print("  protocol = %s" % protocol.id)
    print()


def create_entries(keystone_client):
    rules = [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}",
                        "id": "{0}",
                    }
                }
            ],
            "remote": [
                {
                    "type": "REMOTE_USER"
                }
            ]
        },
        {
            "local": [
                {
                    "group": {
                        "id": "narnians"
                    }
                }
            ],
            "remote": [
                {
                    "type": "REMOTE_USER_GROUPS",
                    "any_one_of": ["narnians"]
                }
            ]
        },
        {
            "local": [
                {
                    "group": {
                        "id": "telmarines"
                    }
                }
            ],
            "remote": [
                {
                    "type": "REMOTE_USER_GROUPS",
                    "any_one_of": ["telmarines"]
                }
            ]
        },
        {
            "local": [
                {
                    "group": {
                        "id": "osprey"
                    }
                }
            ],
            "remote": [
                {
                    "type": "REMOTE_USER_GROUPS",
                    "any_one_of": ["osprey"]
                }
            ]
        },
    ]

    keystone_client.federation.mappings.create(mapping_id='cloudlab',
                                               rules=rules)
    keystone_client.federation.identity_providers.create(id='sssd')
    keystone_client.federation.protocols.create(identity_provider_id='sssd',
                                                protocol_id='kerberos',
                                                mapping_id='cloudlab')
    display(keystone_client, 'Created Protocol')


def delete_entries(keystone_client):
    try:
        keystone_client.federation.mappings.delete(mapping='cloudlab')
    except exceptions.NotFound:
        pass
    try:
        keystone_client.federation.protocols.delete(identity_provider='sssd',
                                                    protocol='kerberos')
    except exceptions.NotFound:
        pass
    try:
        keystone_client.federation.identity_providers.delete(
            identity_provider='sssd')
    except exceptions.NotFound:
        pass


def assign_role_to_group(keystone_client, group_name='osprey', role_name='Member',
                         project_name='demo'):
    group = keystone_client.groups.get(group_name)
    role = keystone_client.roles.find(name=role_name)
    project = keystone_client.projects.find(name=project_name)
    keystone_client.roles.grant(role=role, group=group, project=project)


def main():
    try:
        os_password = os.environ['OS_PASSWORD']
        os_username = os.environ['OS_USERNAME']
        os_auth_url = os.environ['OS_AUTH_URL']
        os_project_name = os.environ['OS_PROJECT_NAME']
        os_ca_cert = os.environ['OS_CA_CERT']

    except KeyError as e:
        print('%s environment variables not set.' % e)
        exit(1)

    auth = v3.Password(auth_url=os_auth_url,
                       username=os_username,
                       password=os_password,
                       user_domain_name='Default',
                       project_domain_name='Default',
                       project_name=os_project_name)

    sess = session.Session(auth=auth, verify=os_ca_cert)

    keystone_client = client.Client(('3', '0'),
                                    session=sess,
                                    endpoint=os_auth_url,
                                    )
    display(keystone_client, 'Start')
    for group in keystone_client.groups.list():
        print("group id = %s" % group.id)
        if group.id == 'narnians':
            group_narnians = group



    #keystone_client.projects.create(name='Castle', domain='default')
    #assign_role_to_group(keystone_client, group_name='telmarines', role_name='Member',
    #                     project_name='Castle')

    #keystone_client.projects.create(name='Woods', domain='default')
    #assign_role_to_group(keystone_client, group_name='narnians', role_name='Member',
    #                     project_name='Woods')

    project_woods  = keystone_client.projects.find(name="Woods")

    for role in keystone_client.roles.list(group=group_narnians,
                                           project=project_woods):
        print("members of group id= %s have  role %s in project %s" %
              (group_narnians.id, role.name, project_woods.name))

    #assign_role_to_group(keystone_client)

    delete_entries(keystone_client)
    create_entries(keystone_client)

if __name__ == "__main__":
    main()