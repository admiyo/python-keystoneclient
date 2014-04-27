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
from keystoneclient import session
from keystoneclient.auth.identity import v3


def display(keystone_client, stage):
    print(stage)
    global provider, protocol
    for provider in keystone_client.federation.identity_providers.list():
        print("provider = %s" % provider.id)
        for protocol in keystone_client.federation.protocols.list(provider):
            print("  protocol = %s" % protocol.id)
    print()


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
    keystone_client.federation.identity_providers.create(id='sssd')
    display(keystone_client, 'Created IdP')
    keystone_client.federation.protocols.create(identity_provider_id='sssd',
                                                protocol_id='kerberos')
    display(keystone_client, 'Created Protocol')

    keystone_client.federation.protocols.delete(identity_provider='sssd',
                                                protocol='kerberos')
    display(keystone_client, 'Deleted Protocol')
    keystone_client.federation.identity_providers.delete(identity_provider='sssd')
    display(keystone_client, 'Deleted Idp')

if __name__ == "__main__":
    main()