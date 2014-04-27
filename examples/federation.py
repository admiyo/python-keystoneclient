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


try:
    OS_PASSWORD = os.environ['OS_PASSWORD']
    OS_USERNAME = os.environ['OS_USERNAME']
    OS_AUTH_URL = os.environ['OS_AUTH_URL']
    OS_PROJECT_NAME = os.environ['OS_PROJECT_NAME']
    OS_CA_CERT = os.environ['OS_CA_CERT']

except KeyError as e:
    print ('%s environment variables not set.' % e)
    exit(1)


auth = v3.Password(auth_url=OS_AUTH_URL,
                   username=OS_USERNAME,
                   password=OS_PASSWORD,
                   user_domain_name='Default',
                   project_domain_name='Default',
                   project_name=OS_PROJECT_NAME)

sess = session.Session(auth=auth, verify=OS_CA_CERT)

keystone_client = client.Client(session=sess, endpoint=OS_AUTH_URL)
keystone_client.federation.identity_providers.list() #create(id='sssd')
