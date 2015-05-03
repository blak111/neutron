# -*- encoding: utf-8 -*-
#
# Copyright © 2012 New Dream Network, LLC (DreamHost)
#
# Author: Doug Hellmann <doug.hellmann@dreamhost.com>
#         Angus Salkeld <asalkeld@redhat.com>
#
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

from oslo.config import cfg
from oslo.middleware import request_id
from pecan import hooks

from neutron import context


class ContextHook(hooks.PecanHook):
    """Configures a request context and attaches it to the request.
    The following HTTP request headers are used:
    X-User-Id or X-User:
        Used for context.user_id.
    X-Tenant-Id or X-Tenant:
        Used for context.tenant.
    X-Auth-Token:
        Used for context.auth_token.
    X-Roles:
        Used for setting context.is_admin flag to either True or False.
        The flag is set to True, if X-Roles contains either an administrator
        or admin substring. Otherwise it is set to False.
    """
    def before(self, state):
        # save an ns lookup
        req = state.request

        user_id = req.headers.get('X-User-Id')
        user_name = req.headers.get('X-User-Name')

        tenant_id = req.headers.get('X-Tenant-Id')
        tenant_name = req.headers.get('X-Project-Name')

        req_id = req.environ.get(request_id.ENV_REQUEST_ID)

        auth_token = req.headers.get('X-Auth-Token')
        roles = [r.strip() for r in req.headers.get('X-Roles', '').split(',')]

        state.request.context = context.Context(
            user_id,
            tenant_id,
            role=roles,
            user_name=user_name,
            tenant_name=tenant_name,
            request_id=req_id,
            auth_token=auth_token
        )
