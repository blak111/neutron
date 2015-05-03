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

import copy
import threading
import os
import time

from oslo.config import cfg
from oslo_middleware import request_id
from oslo_utils import excutils
from pecan import hooks
import simplejson
import webob

from neutron.api.v2 import attributes
from neutron.api.v2 import base as v2base
from neutron.api.v2 import router
from neutron import context
from neutron.common import constants as const
from neutron.common import exceptions
from neutron import manager
from neutron.openstack.common import policy as common_policy
from neutron import policy
from neutron import quota


class ConfigHook(hooks.PecanHook):
    """Attach the configuration object to the reqest so that controllers can
       access it.
    """

    def before(self, state):
        state.request.cfg = cfg.CONF


class NotifierHook(hooks.PecanHook):
    # TODO(kevinbenton): implement
    # dhcp agent notifier
    # ceilo notifier
    # nova notifier
    def before(self, state):
        pass

    def after(self, state):
        pass


class AttributePopulationHook(hooks.PecanHook):

    def before(self, state):
        state.request.prepared_data = {}
        if state.request.method not in ('POST', 'PUT'):
           return
        is_create = state.request.method == 'POST'
        resource = state.request.resource_type
        if not resource:
           return
        state.request.prepared_data = v2base.Controller.prepare_request_body(
            state.request.context, state.request.json, is_create, resource,
            _attributes_for_resource(resource))
        # make the original object available:
        if not is_create:
            obj_id = _pull_id_from_request(state.request)
            attrs = _attributes_for_resource(resource)
            field_list = [name for (name, value) in attrs.iteritems()
                          if (value.get('required_by_policy') or
                              value.get('primary_key') or
                              'default' not in value)]
            plugin = manager.NeutronManager.get_plugin()
            getter = getattr(plugin, 'get_%s' % resource)
            # TODO(kevinbenton): parent_id logic currently in base.py
            obj = getter(state.request.context, obj_id, fields=field_list)
            state.request.original_object = obj


def _pull_id_from_request(request):
    # NOTE(kevinbenton): this sucks
    # Converting /v2.0/ports/dbbdae29-82f6-49cf-b05e-3365bcc95b7a.json
    # into dbbdae29-82f6-49cf-b05e-3365bcc95b7a
    resources = _plural(request.resource_type)
    jsontrail = request.path_info.replace('/v2.0/%s/' % resources, '')
    obj_id = jsontrail.replace('.json', '')
    return obj_id



class ResourceIdentifierHook(hooks.PecanHook):

    def before(self, state):
        # TODO(kevinbenton): find a better way to look this up
        state.request.resource_type = None
        try:
            url_type = state.request.path.split('/')[2].rsplit('.', 1)[0]
        except IndexError:
            return

        for single, plural in router.RESOURCES.items():
            if plural == url_type:
                state.request.resource_type = single
                return


def _plural(rtype):
  return router.RESOURCES[rtype]


class ExceptionTranslationHook(hooks.PecanHook):
    def on_error(self, state, e):
        if type(e) in v2base.FAULT_MAP:
            # NOTE(kevinbenton): should we be suppressing policy error message?
            raise v2base.FAULT_MAP[type(e)](e.message)


class PolicyHook(hooks.PecanHook):
    ACTION_MAP = {'POST': 'create', 'PUT': 'update', 'GET': 'get',
                  'DELETE': 'delete'}

    def before(self, state):
        rtype = state.request.resource_type
        if not rtype:
            return
        is_update = (state.request.method == 'PUT')
        items = _get_resources_from_request(state.request)
        policy.init()
        action = '%s_%s' % (self.ACTION_MAP[state.request.method], rtype)
        for item in items:
            if is_update:
                obj = copy.copy(state.request.original_object)
                obj.update(item)
                obj[const.ATTRIBUTES_TO_UPDATE] = item.keys()
                item = obj
            try:
                policy.enforce(state.request.context, action, item,
                               pluralized=_plural(rtype))
            except common_policy.PolicyNotAuthorized:
                with excutils.save_and_reraise_exception() as ctxt:
                    # If a tenant is modifying it's own object, it's safe to
                    # return a 403. Otherwise, pretend that it doesn't exist
                    # to avoid giving away information.
                    if (is_update and
                            request.context.tenant_id != obj['tenant_id']):
                        ctxt.reraise = False
                msg = _('The resource could not be found.')
                raise webob.exc.HTTPNotFound(msg)


    def after(self, state):
        resource_type = getattr(state.request, 'resource_type', None)
        if not resource_type:
            # can't filter a resource we don't recognize
            return
        try:
            data = state.response.json
        except simplejson.JSONDecodeError:
            return
        if not data:
            return
        if resource_type in data:
            # singular response
            data[resource_type] = self._get_filtered_item(
                state.request.context, resource_type, data[resource_type])
        elif _plural(resource_type) in data:
            # plural response
            plural = _plural(resource_type)
            data[plural] = [self._get_filtered_item(state.request.context,
                                                    resource_type, item)
                            for item in data[plural]]
        state.response.json = data

    def _get_filtered_item(self, context, resource_type, data):
        to_exclude = self._exclude_attributes_by_policy(context,
                                                        resource_type, data)
        return self._filter_attributes(context, data, to_exclude)

    def _filter_attributes(self, context, data, fields_to_strip):
        return dict(item for item in data.iteritems()
                    if (item[0] not in fields_to_strip))

    def _exclude_attributes_by_policy(self, context, resource_type, data):
        """Identifies attributes to exclude according to authZ policies.

        Return a list of attribute names which should be stripped from the
        response returned to the user because the user is not authorized
        to see them.
        """
        attributes_to_exclude = []
        for attr_name in data.keys():
            attr_data = _attributes_for_resource(
                resource_type).get(attr_name)
            if attr_data and attr_data['is_visible']:
                if policy.check(
                    context,
                    # NOTE(kevinbenton): this used to reference a
                    # _plugin_handlers dict, why?
                    'get_%s:%s' % (resource_type, attr_name),
                    data,
                    might_not_exist=True,
                    pluralized=_plural(resource_type)):
                    # this attribute is visible, check next one
                    continue
            # if the code reaches this point then either the policy check
            # failed or the attribute was not visible in the first place
            attributes_to_exclude.append(attr_name)
        return attributes_to_exclude


def _attributes_for_resource(resource):
    if resource not in router.RESOURCES:
        return {}
    return attributes.RESOURCE_ATTRIBUTE_MAP.get(
        _plural(resource), {})


class TranslationHook(hooks.PecanHook):

    def __init__(self):
        # Use thread local storage to make this thread safe in situations
        # where one pecan instance is being used to serve multiple request
        # threads.
        self.local_error = threading.local()
        self.local_error.translatable_error = None

    def before(self, state):
        self.local_error.translatable_error = None

    def after(self, state):
        if hasattr(state.response, 'translatable_error'):
            self.local_error.translatable_error = (
                state.response.translatable_error)


class RequestTimer(hooks.PecanHook):
    def before(self, state):
        state.request.start_time = time.time()

    def after(self, state):
        print "Request time", time.time() - state.request.start_time


def _get_resources_from_request(request):
    resource_type = request.resource_type
    if not resource_type:
        return []
    data = request.prepared_data
    # single item
    if resource_type in data:
        return [data[resource_type]]
    # multiple items
    if router.RESOURCES[resource_type] in data:
        return data[_plural(resource_type)]

    return []



class OwnershipValidationHook(hooks.PecanHook):

    def before(self, state):
        if state.request.method != 'POST':
            return
        items = _get_resources_from_request(state.request)
        for item in items:
            self._validate_network_tenant_ownership(state.request, item)


    def _validate_network_tenant_ownership(self, request, resource_item):
        # TODO(salvatore-orlando): consider whether this check can be folded
        # in the policy engine
        #if (request.context.is_admin or request.context.is_advsvc or
        rtype = request.resource_type
        if rtype not in ('port', 'subnet'):
            return
        plugin = manager.NeutronManager.get_plugin()
        network = plugin.get_network(request.context,
                                     resource_item['network_id'])
        # do not perform the check on shared networks
        if network.get('shared'):
            return

        network_owner = network['tenant_id']

        if network_owner != resource_item['tenant_id']:
            msg = _("Tenant %(tenant_id)s not allowed to "
                    "create %(resource)s on this network")
            raise webob.exc.HTTPForbidden(msg % {
                "tenant_id": resource_item['tenant_id'],
                "resource": rtype,
            })


class QuotaEnforcementHook(hooks.PecanHook):
    def before(self, state):
        if state.request.method != 'POST':
            return
        items = _get_resources_from_request(state.request)
        deltas = {}
        for item in items:
            tenant_id = item['tenant_id']
            try:
                count = quota.QUOTAS.count(state.request.context, rtype,
                                           manager.NeutronManager.get_plugin(),
                                           _plural(rtype), tenant_id)
                delta = deltas.get(tenant_id, 0) + 1
                kwargs = {rtype: count + delta}
            except exceptions.QuotaResourceUnknown as e:
                # We don't want to quota this resource
                LOG.debug(e)
            else:
                quota.QUOTAS.limit_check(state.request.context, tenant_id,
                                         **kwargs)



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
        user_id = state.request.headers.get('X-User-Id')
        user_id = state.request.headers.get('X-User', user_id)
        user_name = state.request.headers.get('X-User-Name', '')
        tenant_id = state.request.headers.get('X-Tenant-Id')
        tenant = state.request.headers.get('X-Tenant', tenant_id)
        tenant_name = state.request.headers.get('X-Tenant-Name', tenant)
        domain_id = state.request.headers.get('X-User-Domain-Id')
        domain_name = state.request.headers.get('X-User-Domain-Name')
        auth_token = state.request.headers.get('X-Auth-Token')
        creds = {'roles': state.request.headers.get('X-Roles', '').split(',')}
        req_id = state.request.headers.get(request_id.ENV_REQUEST_ID)
        # TODO(kevinbenton): remove
        #is_admin = policy.check('admin', state.request.headers, creds)
        """
        state.request.context = context.RequestContext(
            auth_token=auth_token,
            user=user_id,
            tenant=tenant,
            domain_id=domain_id,
            domain_name=domain_name)
            is_admin=is_admin)
        """
        # Create a context with the authentication data
        ctx = context.Context(user_id, tenant_id=tenant_id, roles=creds['roles'],
                              user_name=user_name, tenant_name=tenant_name,
                              request_id=req_id, auth_token=auth_token)

        # Inject the context...
        #req.environ['neutron.context'] = ctx
        state.request.context = ctx
