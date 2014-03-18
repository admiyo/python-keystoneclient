# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging

import six

from keystoneclient import _discover
from keystoneclient import exceptions
from keystoneclient import session as client_session
from keystoneclient.v2_0 import client as v2_client
from keystoneclient.v3 import client as v3_client


_logger = logging.getLogger(__name__)


_CLIENT_VERSIONS = {2: v2_client.Client,
                    3: v3_client.Client}


def available_versions(url, session=None, **kwargs):
    if not session:
        session = client_session.Session.construct(kwargs)

    return _discover.get_version_data(session, url)


class Discover(_discover.Discover):
    """A means to discover and create clients depending on the supported API
    versions on the server.

    Querying the server is done on object creation and every subsequent method
    operates upon the data that was retrieved.
    """

    def __init__(self, session=None, **kwargs):
        """Construct a new discovery object.

        The connection parameters associated with this method are the same
        format and name as those used by a client (see
        keystoneclient.v2_0.client.Client and keystoneclient.v3.client.Client).
        If not overridden in subsequent methods they will also be what is
        passed to the constructed client.

        In the event that auth_url and endpoint is provided then auth_url will
        be used in accordance with how the client operates.

        The initialization process also queries the server.

        :param Session session: A session object that will be used for
                                communication. Clients will also be constructed
                                with this session.
        :param string auth_url: Identity service endpoint for authorization.
                                (optional)
        :param string endpoint: A user-supplied endpoint URL for the identity
                                service. (optional)
        :param string original_ip: The original IP of the requesting user
                                   which will be sent to identity service in a
                                   'Forwarded' header. (optional)
                                   DEPRECATED: use the session object. This is
                                   ignored if a session is provided.
        :param boolean debug: Enables debug logging of all request and
                              responses to the identity service.
                              default False (optional)
                              DEPRECATED: use the session object. This is
                              ignored if a session is provided.
        :param string cacert: Path to the Privacy Enhanced Mail (PEM) file
                              which contains the trusted authority X.509
                              certificates needed to established SSL connection
                              with the identity service. (optional)
                              DEPRECATED: use the session object. This is
                              ignored if a session is provided.
        :param string key: Path to the Privacy Enhanced Mail (PEM) file which
                           contains the unencrypted client private key needed
                           to established two-way SSL connection with the
                           identity service. (optional)
                           DEPRECATED: use the session object. This is
                           ignored if a session is provided.
        :param string cert: Path to the Privacy Enhanced Mail (PEM) file which
                            contains the corresponding X.509 client certificate
                            needed to established two-way SSL connection with
                            the identity service. (optional)
                            DEPRECATED: use the session object. This is
                            ignored if a session is provided.
        :param boolean insecure: Does not perform X.509 certificate validation
                                 when establishing SSL connection with identity
                                 service. default: False (optional)
                                 DEPRECATED: use the session object. This is
                                 ignored if a session is provided.
        """

        if not session:
            session = client_session.Session.construct(kwargs)

        kwargs['session'] = session

        url = None
        endpoint = kwargs.pop('endpoint', None)
        auth_url = kwargs.pop('auth_url', None)

        if endpoint:
            self._use_endpoint = True
            url = endpoint
        elif auth_url:
            self._use_endpoint = False
            url = auth_url

        if not url:
            raise exceptions.DiscoveryFailure('Not enough information to '
                                              'determine URL. Provide either '
                                              'auth_url or endpoint')

        self._client_kwargs = kwargs
        super(Discover, self).__init__(session, url)

    def available_versions(self, unstable=False):
        """Return a list of identity APIs available on the server and the data
        associated with them.

        :param bool unstable: Accept endpoints not marked 'stable'. (optional)

        :returns: A List of dictionaries as presented by the server. Each dict
                  will contain the version and the URL to use for the version.
                  It is a direct representation of the layout presented by the
                  identity API.

        Example::

            >>> from keystoneclient import discover
            >>> disc = discover.Discovery(auth_url='http://localhost:5000')
            >>> disc.available_versions()
                [{'id': 'v3.0',
                    'links': [{'href': u'http://127.0.0.1:5000/v3/',
                               'rel': u'self'}],
                  'media-types': [
                      {'base': 'application/json',
                       'type': 'application/vnd.openstack.identity-v3+json'},
                      {'base': 'application/xml',
                       'type': 'application/vnd.openstack.identity-v3+xml'}],
                  'status': 'stable',
                  'updated': '2013-03-06T00:00:00Z'},
                 {'id': 'v2.0',
                  'links': [{'href': u'http://127.0.0.1:5000/v2.0/',
                             'rel': u'self'},
                            {'href': u'...',
                             'rel': u'describedby',
                             'type': u'application/pdf'}],
                  'media-types': [
                      {'base': 'application/json',
                       'type': 'application/vnd.openstack.identity-v2.0+json'},
                      {'base': 'application/xml',
                       'type': 'application/vnd.openstack.identity-v2.0+xml'}],
                  'status': 'stable',
                  'updated': '2013-03-06T00:00:00Z'}]
        """
        return self.raw_version_data(unstable=unstable)

    def raw_version_data(self, unstable=False, **kwargs):
        if unstable:
            kwargs.setdefault('allow_experimental', True)
            kwargs.setdefault('allow_unknown', True)

        return super(Discover, self).raw_version_data(**kwargs)

    def create_client(self, version=None, unstable=False, **kwargs):
        """Factory function to create a new identity service client.

        :param tuple version: The required version of the identity API. If
                              specified the client will be selected such that
                              the major version is equivalent and an endpoint
                              provides at least the specified minor version.
                              For example to specify the 3.1 API use (3, 1).
                              (optional)
        :param bool unstable: Accept endpoints not marked 'stable'. (optional)
        :param kwargs: Additional arguments will override those provided to
                       this object's constructor.

        :returns: An instantiated identity client object.

        :raises: DiscoveryFailure if the server response is invalid
        :raises: VersionNotAvailable if a suitable client cannot be found.
        """
        all_versions = None
        version_data = None

        if version:
            version_data = self.data_for(version)
        else:
            # if no version specified pick the latest one
            all_versions = self.version_data(unstable=unstable)
            if all_versions:
                version_data = all_versions[-1]

        if not version_data:
            msg = 'Could not find a suitable endpoint'

            if version:
                msg = '%s for client version: %s' % (msg, version)

            if all_versions:
                available = ', '.join(['.'.join([str(v) for v in d])
                                       for d in six.iterkeys(all_versions)])
                msg = '%s. Available_versions are: %s' % (msg, available)

            raise exceptions.VersionNotAvailable(msg)

        # Get the client for the version requested that was returned
        try:
            client_class = _CLIENT_VERSIONS[version_data['version'][0]]
        except KeyError:
            msg = 'No client available for version: %s'
            raise exceptions.DiscoveryFailure(msg % version_data['version'])

        # reverse dict.update
        for k, v in six.iteritems(self._client_kwargs):
            kwargs.setdefault(k, v)

        # restore the url to either auth_url or endpoint depending on what
        # was initially given
        if self._use_endpoint:
            kwargs['auth_url'] = None
            kwargs['endpoint'] = version_data['url']
        else:
            kwargs['auth_url'] = version_data['url']
            kwargs['endpoint'] = None

        return client_class(**kwargs)
