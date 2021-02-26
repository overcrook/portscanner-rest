import functools
import asyncio
import inspect
import json
import portscan
from portscan import POLLIN, POLLOUT
from aiohttp import web

DEFAULT_METHODS = ['GET']

def update_reader(fut, scan, callback, old_pollin, new_pollin):
    if old_pollin == new_pollin:
        return

    loop = asyncio.get_running_loop()

    if new_pollin:
        loop.add_reader(scan.scan_fd, callback, fut, scan)
    else:
        loop.remove_reader(scan.scan_fd)

def update_writer(fut, scan, callback, old_pollout, new_pollout):
    if old_pollout == new_pollout:
        return

    loop = asyncio.get_running_loop()

    if new_pollout:
        loop.add_writer(scan.scan_fd, callback, fut, scan)
    else:
        loop.remove_writer(scan.scan_fd)


def scan_async_process(fut, scan, callback):
    # Сохраняем текущее состояние ожидаемых событий
    old_events = scan.events

    # Выполняем требуемую обработку
    callback()

    # Обрабатываем изменение битовой маски ожидаемых событий
    if old_events != scan.events:
        update_reader(fut, scan, scan_asyncread,  old_events & POLLIN,  scan.events & POLLIN)
        update_writer(fut, scan, scan_asyncwrite, old_events & POLLOUT, scan.events & POLLOUT)

    # Как только сканер перестает ожидать и POLLIN, и POLLOUT, работа завершена
    if scan.events == 0:
        loop = asyncio.get_running_loop()
        loop.remove_reader(scan.timer_fd)
        fut.set_result(scan.close())


def scan_asyncread(fut, scan):
    scan_async_process(fut, scan, scan.read)


def scan_asyncwrite(fut, scan):
    scan_async_process(fut, scan, scan.write)


def scan_asynctimeout(fut, scan):
    scan_async_process(fut, scan, scan.timeout)


async def asyncscan(ipaddress, port_start, port_end):
    scan = portscan.new(ipaddress, port_start, port_end)
    loop = asyncio.get_running_loop()
    fut  = loop.create_future()

    loop.add_writer(scan.scan_fd,  scan_asyncwrite,   fut, scan)
    loop.add_reader(scan.scan_fd,  scan_asyncread,    fut, scan)
    loop.add_reader(scan.timer_fd, scan_asynctimeout, fut, scan)

    return await fut


class RestEndpoint:
    def __init__(self):
        self.methods = {}

        for method_name in DEFAULT_METHODS:
            method = getattr(self, method_name.lower(), None)
            if method:
                self.register_method(method_name, method)

    def register_method(self, method_name, method):
        self.methods[method_name.upper()] = method

    async def dispatch(self, request):
        print(self.methods)
        method = self.methods.get(request.method.upper())
        if not method:
            raise web.HTTPMethodNotAllowed('', DEFAULT_METHODS)

        wanted_args = list(inspect.signature(method).parameters.keys())
        available_args = request.match_info.copy()
        available_args.update({'request': request})

        unsatisfied_args = set(wanted_args) - set(available_args.keys())
        if unsatisfied_args:
            # Expected match info that doesn't exist
            raise web.HTTPBadRequest('')

        return await method(**{arg_name: available_args[arg_name] for arg_name in wanted_args})

class RangeScanRestEndpoint(RestEndpoint):
    def __init__(self, resource: web.Resource):
        super().__init__()
        self.resource = resource

    async def get(self, ipaddress, port_start, port_end) -> web.Response:
        ret = await asyncscan(ipaddress, int(port_start), int(port_end))

        body = self.resource.encode([
            {'port': item.port, 'state': item.status}
            for item in ret
        ])
        return web.Response(status = 200, body = body, content_type = 'application/json')

class ScanRestEndpoint(RestEndpoint):
    def __init__(self, resource: web.Resource, scan_range: RangeScanRestEndpoint):
        super().__init__()
        self.scan_range = scan_range
        self.resource   = resource

    async def get(self, ipaddress, port_start) -> web.Response:
        return await self.scan_range.get(ipaddress, port_start, 0)


class PortscanRest:
    def __init__(self):
        self.scan_range_endpoint = RangeScanRestEndpoint(self)
        self.scan_endpoint       = ScanRestEndpoint(self, self.scan_range_endpoint)

    @staticmethod
    def encode(data):
        return json.dumps(data, indent=4).encode('utf-8')

    def register(self, router: web.UrlDispatcher):
        router.add_route('get', '/scan/{ipaddress}/{port_start}', self.scan_endpoint.dispatch)
        router.add_route('get', '/scan/{ipaddress}/{port_start}/{port_end}', self.scan_range_endpoint.dispatch)
