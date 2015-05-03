from neutron import manager

from pecan import expose as p_expose
from pecan import redirect
from pecan import request
from webob.exc import status_map

def expose(*args, **kwargs):
    kwargs.setdefault('content_type', 'application/json')
    kwargs.setdefault('template', 'json')
    return p_expose(*args, **kwargs)

class RootController(object):

    @expose(generic=True, template='index.html')
    def index(self):
        return dict()

    @index.when(method='POST')
    def index_post(self, q):
        redirect('http://pecan.readthedocs.org/en/latest/search.html?q=%s' % q)

    @expose()
    def error(self, status):
        try:
            status = int(status)
        except ValueError:  # pragma: no cover
            status = 500
        message = getattr(status_map.get(status), 'explanation', '')
        return dict(status=status, message=message, hello='world')


class V2Controller(object):

    @property
    def _plugin(self):
        return manager.NeutronManager.get_plugin()

    def error(self, status):
        return dict(status=status, message='hi')

    @expose(generic=True)
    def _default(self, *args, **kwargs):
        pass

    @_default.when(method='GET', content_type='application/json',
                   template='json')
    def _get(self, endpoint, *args, **kwargs):
        # list request
        # TODO(kevinbenton): allow fields after policy enforced fields present
        fields = kwargs.pop('fields', None)
        _listify = lambda x: x if isinstance(x, list) else [x]
        filters = {k: _listify(v) for k, v in kwargs.items()}
        if not args:
            lister= getattr(self._plugin, 'get_%s' % endpoint)
            return {endpoint: lister(request.context, filters=filters)}
        item_id = args[0]
        getter = getattr(self._plugin, 'get_%s' % request.resource_type)
        return {request.resource_type: getter(request.context, item_id)}

    @_default.when(method='POST', content_type='application/json',
                   template='json')
    def _create(self, *args, **kwargs):
        # TODO(kevinbenton): bulk!
        doer = getattr(self._plugin, 'create_%s' % request.resource_type)
        return doer(request.context, request.prepared_data)

    @_default.when(method='PUT', content_type='application/json',
                   template='json')
    def _update(self, endpoint, item_id, *args, **kwargs):
        # TODO(kevinbenton): bulk?
        updater = getattr(self._plugin, 'update_%s' % request.resource_type)
        return updater(request.context, item_id, request.prepared_data)

    @_default.when(method='DELETE', content_type='application/json',
                   template='json')
    def _delete(self, endpoint, item_id, *args, **kwargs):
        # TODO(kevinbenton): bulk?
        deleter = getattr(self._plugin, 'delete_%s' % request.resource_type)
        return deleter(request.context, item_id)

setattr(RootController, 'v2.0', V2Controller())
