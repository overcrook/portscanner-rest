from aiohttp.web import Application, run_app
from portscan_rest import PortscanRest

app = Application()
scan_resource = PortscanRest()
scan_resource.register(app.router)

if __name__ == '__main__':
    run_app(app)
