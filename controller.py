#!/usr/bin/env python
from __future__ import print_function

import logging

LOG_FORMAT = '%(asctime)s %(levelname)s %(pathname)s:%(lineno)s: %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG)

import os
import signal
import sys
import six
import threading
import time
import pprint
import psutil
import atexit
import argparse
import jinja2
from flask import Flask, Response, url_for, render_template, jsonify, request, current_app
from flask.json import JSONEncoder
from flask_reverse_proxy import ReverseProxied

from tornado.netutil import Resolver
from tornado import gen
import socket

# Defaults
DEFAULT_WAIT_DELAY = 0.1
DEFAULT_CONTROL_SOCKET_PATH = '/var/run/connector.sock'
DEFAULT_NGINX_PID_FILE = '/var/log/nginx/nginx.pid'
DEFAULT_NGINX_CONF_FILE = '/etc/nginx/conf.d/default.conf'
DEFAULT_NGINX_PORT = 8080
DEFAULT_PORT = 9090
DEFAULT_HOST = '0.0.0.0'


class PortWatcher(object):
    INSTANCE = None

    @classmethod
    def instance(cls):
        return cls.INSTANCE

    @classmethod
    def start_instance(cls, *args, **kwargs):
        if cls.INSTANCE is None:
            cls.INSTANCE = cls(*args, **kwargs)
        return cls.INSTANCE

    def __init__(self, ports_changed_cb=None, wait_delay=DEFAULT_WAIT_DELAY):
        self._ports_changed_cb = ports_changed_cb
        self._wait_delay = wait_delay
        self._thread_lock = threading.RLock()
        self._thread = threading.Thread(name='PortWatchLoop', target=self._update_ports)
        self._thread.daemon = True
        self._stop_thread = False
        self._ports = set()
        self._thread.start()
        logging.info('Started port watcher')

    @property
    def ports(self):
        with self._thread_lock:
            return self._ports.copy()

    def _update_ports(self):
        while True:
            with self._thread_lock:
                if self._stop_thread:
                    return

            # get sshd ports
            ports = set([])
            try:
                for proc in psutil.process_iter():
                    if proc.name() == 'sshd':
                        for conn in proc.connections():
                            laddr_ip = conn.laddr[0]
                            laddr_port = conn.laddr[1]
                            if conn.status == psutil.CONN_LISTEN and \
                                    laddr_port != 22 and \
                                    laddr_ip in ('127.0.0.1', 'localhost'):
                                # logging.info('Connection %r', conn)
                                ports.add(laddr_port)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                try:
                    for conn in psutil.net_connections('inet'):
                        laddr_ip = conn.laddr[0]
                        laddr_port = conn.laddr[1]
                        if conn.status == psutil.CONN_LISTEN and \
                                laddr_port != 22 and \
                                laddr_ip in ('127.0.0.1', 'localhost'):
                            if conn.pid is None and laddr_port > 1023:
                                # logging.info('Connection %r', conn)
                                ports.add(laddr_port)  # unsafe
                            else:
                                for p in psutil.process_iter():
                                    if p.pid == conn.pid and 'sshd' in p.name():
                                        # logging.info('Connection %r', conn)
                                        ports.add(laddr_port)
                                        break
                except psutil.AccessDenied:
                    logging.exception('Could not get any information about ports')

            notify_ports = None
            with self._thread_lock:
                if self._ports != ports:
                    logging.info('Ports changed from %s to %s', self._ports, ports)
                    if self._ports_changed_cb:
                        notify_ports = ports.copy()
                    self._ports = ports

            if notify_ports is not None:
                self._ports_changed_cb(notify_ports)
                del notify_ports

            time.sleep(self._wait_delay)

    def stop(self):
        with self._thread_lock:
            if self._stop_thread:
                return
            self._stop_thread = True
        self._thread.join()


class RegisteredPort(object):
    def __init__(self, port, name, type, description):
        self.port = port
        self.name = name
        self.type = type
        self.description = description

    def __repr__(self):
        return 'RegisteredPort(port=%r, name=%r, type=%r, description=%r' % \
               (self.port, self.name, self.type, self.description)

    def to_json(self):
        return {'port': self.port,
                'registered': True,
                'name': self.name,
                'type': self.type,
                'description': self.description
                }


class PortManagerException(Exception):
    def __init__(self, message):
        self.message = message
        super(PortManagerException, self).__init__(message)


class PortManager(object):

    def __init__(self, port_registered_cb=None, port_unregistered_cb=None):
        self.registered_ports_by_port = {}
        self.registered_ports_by_name = {}
        self.bound_ports = set()
        self.port_registered_cb = port_registered_cb
        self.port_unregistered_cb = port_unregistered_cb

    def register(self, port, name, type='tcp', description=None):
        if port not in self.bound_ports:
            raise PortManagerException('Port {} is not bound'.format(port))
        if port in self.registered_ports_by_port:
            raise PortManagerException('Port {} is already registered'.format(port))
        if name in self.registered_ports_by_name:
            raise PortManagerException('Port with name {} does already exist'.format(name))
        rport = RegisteredPort(port=port, name=name, type=type, description=description)
        self.registered_ports_by_port[port] = rport
        self.registered_ports_by_name[name] = rport
        if self.port_registered_cb:
            self.port_registered_cb(rport)
        return rport

    def get_by_port(self, port):
        return self.registered_ports_by_port.get(port, None)

    def get_by_name(self, name):
        return self.registered_ports_by_name.get(name, None)

    def update_accessible_ports(self, ports):
        removed_ports = self.bound_ports - ports
        self.bound_ports = ports.copy()
        for port in removed_ports:
            self.unregister_by_port(port)

    def unregister_by_port(self, port):
        rport = self.registered_ports_by_port.get(port, None)
        if rport is None:
            return False
        assert port == rport.port
        del self.registered_ports_by_port[port]
        del self.registered_ports_by_name[rport.name]
        if self.port_unregistered_cb:
            self.port_unregistered_cb(rport)
        return True

    def unregister_by_name(self, name):
        rport = self.registered_ports_by_name.get(name, None)
        if rport is None:
            return False
        assert name == rport.name
        del self.registered_ports_by_name[name]
        del self.registered_ports_by_port[rport.port]
        if self.port_unregistered_cb:
            self.port_unregistered_cb(rport)
        return True

    def unregister(self, obj):
        if isinstance(obj, RegisteredPort):
            return self.unregister_by_port(obj.port)
        if isinstance(obj, six.integer_types):
            return self.unregister_by_port(obj)
        else:
            return self.unregister_by_name(obj)

    def to_json(self):
        d = []
        for v in six.itervalues(self.registered_ports_by_port):
            d.append(v.to_json())
        for p in self.bound_ports:
            if p not in self.registered_ports_by_port:
                d.append({'port': p, 'registered': False})
        return d


class NginxTemplateGenerator(object):

    def __init__(self,
                 nginx_port=DEFAULT_NGINX_PORT,
                 nginx_conf_file=DEFAULT_NGINX_CONF_FILE,
                 nginx_pid_file=DEFAULT_NGINX_PID_FILE,
                 controller_port=DEFAULT_PORT):
        self.nginx_port = nginx_port
        self.nginx_conf_file = nginx_conf_file
        self.nginx_pid_file = nginx_pid_file
        self.controller_port = controller_port
        dir = os.path.dirname(__file__)
        self.env = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.join(dir, 'templates')))
        self.template = self.env.get_template('default.conf.j2')

    def generate(self, port_manager):
        output = self.template.render(
            controller_port=self.controller_port,
            nginx_port=self.nginx_port,
            bound_ports=port_manager.bound_ports,
            registered_ports_by_port=port_manager.registered_ports_by_port,
            registered_ports_by_name=port_manager.registered_ports_by_name)
        with open(self.nginx_conf_file, 'wb') as fd:
            fd.write(output)

    def reload_nginx_config(self):
        try:
            with open(self.nginx_pid_file, 'r') as fd:
                pid = int(fd.read().strip())
                os.kill(pid, signal.SIGHUP)
                return True
        except Exception:
            logging.exception('Could not reload nginx configuration')
            return False


# Global Data

LOCK = threading.RLock()
PORT_MANAGER = None  # Shared, locked by LOCK
NGINX_TEMPLATE_GEN = None  # Shared, locked by LOCK


class CustomJSONEncoder(JSONEncoder):

    def default(self, obj):
        if isinstance(obj, PortManager):
            return obj.to_json()
        elif isinstance(obj, RegisteredPort):
            return obj.to_json()
        return JSONEncoder.default(self, obj)


app = Flask(__name__)
app.wsgi_app = ReverseProxied(app.wsgi_app)
app.json_encoder = CustomJSONEncoder
control_app = Flask(__name__)
control_app.json_encoder = CustomJSONEncoder

HTTP_OK = 200
HTTP_NO_CONTENT = 204
HTTP_BAD_REQUEST = 400
HTTP_NOT_FOUND = 404
HTTP_INTERNAL_SERVER_ERROR = 500
HTTP_NOT_IMPLEMENTED = 501


def error_response(message, status_code=HTTP_INTERNAL_SERVER_ERROR):
    response = jsonify({'error': message, 'status': status_code})
    response.status_code = status_code
    return response


def bad_request(message):
    return error_response(message=message, status_code=HTTP_BAD_REQUEST)


class BadRequestError(Exception):
    def __init__(self, message):
        self.message = message
        super(BadRequestError, self).__init__(message)


@app.errorhandler(BadRequestError)
@control_app.errorhandler(BadRequestError)
def on_bad_request_error(error):
    return bad_request(error.message)


@app.errorhandler(PortManagerException)
@control_app.errorhandler(PortManagerException)
def on_port_manager_exception(error):
    return bad_request('PortManager error: ' + error.message)


@app.route("/", methods=["GET"])
def get_root():
    global PORT_MANAGER, LOCK
    with LOCK:
        return render_template("index.html",
                               bound_ports=PORT_MANAGER.bound_ports,
                               registered_ports_by_port=PORT_MANAGER.registered_ports_by_port,
                               registered_ports_by_name=PORT_MANAGER.registered_ports_by_name)


@control_app.route("/", methods=["GET"])
def control_get_root():
    return "Control server"


@control_app.route("/ports/")
@app.route("/ports/")
def get_ports():
    with LOCK:
        return jsonify(PORT_MANAGER)


@app.route("/reload_nginx_config")
def get_reload_nginx_config():
    if NGINX_TEMPLATE_GEN.reload_nginx_config():
        return 'Success'
    else:
        return 'Reload failed'


def default_value(value, default=None):
    if not value:
        return default
    return value


@control_app.route("/ports/<port>", methods=["GET", "PUT", "DELETE"])
def control_ports(port):
    if request.method == "GET":
        with LOCK:
            try:
                port = int(port)
                if port not in PORT_MANAGER.bound_ports:
                    return error_response('Port is not bound', HTTP_NOT_FOUND)
                rport = PORT_MANAGER.get_by_port(port)
                if rport is None:
                    return jsonify({'port': port, 'registered': False})
            except ValueError:
                rport = PORT_MANAGER.get_by_name(port)
                if rport is None:
                    return error_response('No port with name {}'.format(port), HTTP_NOT_FOUND)
            else:
                return jsonify(rport)
    elif request.method == "PUT":
        data = request.get_json(silent=True)
        if data is None:
            return bad_request("No json data in body")
        try:
            port = int(port)
        except ValueError:
            return bad_request('Port must be an integer')
        name = six.text_type(default_value(data.get("name"), default=port))
        description = six.text_type(default_value(data.get("description"), default=""))
        type = six.text_type(default_value(data.get("type"), default="tcp"))
        with LOCK:
            if port not in PORT_MANAGER.bound_ports:
                return error_response('Port is not bound', HTTP_NOT_FOUND)
            if PORT_MANAGER.get_by_port(port) is not None:
                return bad_request("Port is already registered")
            if PORT_MANAGER.get_by_name(name) is not None:
                return bad_request("Name is already used")
            return jsonify(PORT_MANAGER.register(port, name, type, description))
    elif request.method == "DELETE":
        with LOCK:
            try:
                port = int(port)
                if port not in PORT_MANAGER.bound_ports:
                    return error_response('Port is not bound', HTTP_NOT_FOUND)
                if not PORT_MANAGER.unregister_by_port(port):
                    return bad_request("Port is not registered")
            except ValueError:
                if not PORT_MANAGER.unregister_by_name(port):
                    return error_response('No port with name {}'.format(port), HTTP_NOT_FOUND)
            return jsonify({})


@app.route("/api/debug/flask/", methods=["GET"])
@control_app.route("/api/debug/flask/", methods=["GET"])
def debug_flask():
    import urllib

    output = ['Rules:']
    for rule in current_app.url_map.iter_rules():

        options = {}
        for arg in rule.arguments:
            options[arg] = "[{0}]".format(arg)

        if rule.methods:
            methods = ','.join(rule.methods)
        else:
            methods = 'GET'
        url = url_for(rule.endpoint, **options)
        line = urllib.unquote("{:50s} {:20s} {}".format(rule.endpoint, methods, url))
        output.append(line)

    output.append('')
    output.append('Request environment:')
    for k, v in six.iteritems(request.environ):
        output.append("{0}: {1}".format(k, pprint.pformat(v, depth=5)))

    return Response('\n'.join(output), mimetype='text/plain')


class UnixResolver(Resolver):
    def initialize(self, socket_file, resolver):
        self.socket_file = socket_file
        self.resolver = resolver

    def close(self):
        self.resolver.close()

    @gen.coroutine
    def resolve(self, host, port, *args, **kwargs):
        if host == 'unixsocket':
            raise gen.Return([(socket.AF_UNIX, self.socket_file)])
        result = yield self.resolver.resolve(host, port, *args, **kwargs)
        raise gen.Return(result)


def start_server(args):
    from tornado.wsgi import WSGIContainer
    from tornado.httpserver import HTTPServer
    from tornado.ioloop import IOLoop
    from tornado.netutil import bind_unix_socket

    logging.info('Run on host %s:%i', args.host, args.port)

    http_server = HTTPServer(WSGIContainer(app))
    http_server.listen(args.port, args.host)

    if args.control_unix_socket:
        control_server = HTTPServer(WSGIContainer(control_app))
        socket = bind_unix_socket(args.control_unix_socket, mode=0o666)
        control_server.add_socket(socket)
        logging.info('Run control server on unix socket %s', args.control_unix_socket)

    global NGINX_TEMPLATE_GEN, PORT_MANAGER, LOCK

    NGINX_TEMPLATE_GEN = NginxTemplateGenerator(nginx_port=args.nginx_port,
                                                nginx_conf_file=args.nginx_conf_file,
                                                nginx_pid_file=args.nginx_pid_file,
                                                controller_port=args.port)

    def nginx_regenerate_conf():
        NGINX_TEMPLATE_GEN.generate(PORT_MANAGER)
        NGINX_TEMPLATE_GEN.reload_nginx_config()

    PORT_MANAGER = PortManager(port_registered_cb=lambda rport: nginx_regenerate_conf(),
                               port_unregistered_cb=lambda rport: nginx_regenerate_conf())

    nginx_regenerate_conf()

    def on_ports_changed(new_ports):
        with LOCK:
            PORT_MANAGER.update_accessible_ports(new_ports)

    PortWatcher.start_instance(ports_changed_cb=on_ports_changed, wait_delay=args.wait_delay)

    loop = IOLoop.current()

    def stop_ioloop():
        logging.info('Stopping IOLoop')
        loop.stop()

    def signal_term_handler(signal, frame):
        print('Got signal {}, exiting'.format(signal), file=sys.stderr)
        stop_ioloop()
        sys.exit(0)

    def on_exit():
        if args.control_unix_socket:
            os.unlink(args.control_unix_socket)

    signal.signal(signal.SIGTERM, signal_term_handler)
    signal.signal(signal.SIGINT, signal_term_handler)
    atexit.register(on_exit)

    loop.start()


def register_port(args):
    from tornado import gen, ioloop
    from tornado.httpclient import HTTPError
    from tornado.httpclient import AsyncHTTPClient
    import json

    if not os.path.exists(args.control_unix_socket):
        print("Socket file {} does not exist !".format(args.control_unix_socket), file=sys.stderr)
        sys.exit(1)

    @gen.coroutine
    def do_register():
        resolver = UnixResolver(socket_file=args.control_unix_socket, resolver=Resolver())
        AsyncHTTPClient.configure(None, resolver=resolver)
        client = AsyncHTTPClient()
        mtype = 'application/json'
        headers = {'Content-Type': mtype}
        body = json.dumps({"name": args.name, "type": args.type, "description": args.description})
        try:
            response = yield client.fetch('http://unixsocket/ports/{}'.format(args.port),
                                          method='PUT',
                                          headers=headers,
                                          body=body)
        except HTTPError as he:
            print("Could not register port: {}".format(he), file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            logging.exception("Could not register port")
            sys.exit(1)
        print(response.body)

    ioloop.IOLoop.current().run_sync(do_register)


def unregister_port(args):
    from tornado import gen, ioloop
    from tornado.httpclient import HTTPError
    from tornado.httpclient import AsyncHTTPClient
    import json

    if not os.path.exists(args.control_unix_socket):
        print("Socket file {} does not exist !".format(args.control_unix_socket), file=sys.stderr)
        sys.exit(1)

    @gen.coroutine
    def do_unregister():
        resolver = UnixResolver(socket_file=args.control_unix_socket, resolver=Resolver())
        AsyncHTTPClient.configure(None, resolver=resolver)
        client = AsyncHTTPClient()
        try:
            response = yield client.fetch('http://unixsocket/ports/{}'.format(args.port),
                                          method='DELETE')
        except HTTPError as he:
            print("Could not unregister port: {}".format(he), file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            logging.exception("Could not unregister port")
            sys.exit(1)
        print(response.body)

    ioloop.IOLoop.current().run_sync(do_unregister)


def main():
    # from tornado.options import define, options
    #
    # define("port", default=9090, help="listen on the given port", type=int)
    # define("host", default="0.0.0.0", help="listen on the given host")
    # define("control_unix_socket", default=DEFAULT_CONTROL_SOCKET_PATH, help="path to the control unix socket to bind")
    # define("nginx_pid_file", default=DEFAULT_NGINX_PID_FILE, help="Location of nginx PID file")
    # define("nginx_conf_file", default=DEFAULT_NGINX_CONF_FILE, help="Location of nginx conf file")

    parser = argparse.ArgumentParser(
        description="Connector Controller",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--debug", help='debug mode', action="store_true")
    parser.add_argument("--control-unix-socket", default=DEFAULT_CONTROL_SOCKET_PATH,
                        help="path to the control unix socket to bind")

    subparsers = parser.add_subparsers()

    start_p = subparsers.add_parser('start', help='start server')
    start_p.add_argument("-p", "--port", default=DEFAULT_PORT, help="listen on the given port", type=int)
    start_p.add_argument("--host", default=DEFAULT_HOST, help="listen on the given host")
    start_p.add_argument("--wait-delay", default=DEFAULT_WAIT_DELAY, help="wait delay in seconds between port checks")
    start_p.add_argument("--nginx-port", default=DEFAULT_NGINX_PORT, help="nginx server port")
    start_p.add_argument("--nginx-pid-file", default=DEFAULT_NGINX_PID_FILE, help="Location of nginx PID file")
    start_p.add_argument("--nginx-conf-file", default=DEFAULT_NGINX_CONF_FILE, help="Location of nginx conf file")
    start_p.set_defaults(func=start_server)

    register_p = subparsers.add_parser('register', help='register port')
    register_p.add_argument("port", help="port number", type=int)
    register_p.add_argument("-n", "--name", default=None, help="port name")
    register_p.add_argument("-t", "--type", default=None, help="port type")
    register_p.add_argument("-d", "--description", default=None, help="port description")
    register_p.set_defaults(func=register_port)

    unregister_p = subparsers.add_parser('unregister', help='unregister port')
    unregister_p.add_argument("port", help="port number or name")
    unregister_p.set_defaults(func=unregister_port)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
