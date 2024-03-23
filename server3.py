import sys
import subprocess
import os
import re
import json
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse
import http.server
import ssl
from urllib.parse import urlparse
from argparse import ArgumentParser
# from tkinter import messagebox

cli = ArgumentParser(description='Web ADB -- a simple server for monitoring Android devices')
cli.add_argument('-p', '--port', type=int, dest='port', default=8080)
cli.add_argument('--cert-file', dest='certfile')
cli.add_argument('--adb-path', dest='adbpath', default=os.environ.get('WEB_ADB'))
arguments = cli.parse_args()

def _adb(args, device=None):
    base = [arguments.adbpath]
    if device is not None:
        base = base + ['-s', device]

    args = base + args
    p = subprocess.Popen([str(arg) for arg in args], stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return (p.returncode, stdout, stderr)

def _getprop(device, property, default):
    (rc, out, _) = _adb(['shell', 'getprop', property], device=device)

    if not rc == 0:
        return default
    elif out.strip():
        return out.strip().decode('utf-8')
    else:
        return default

# adb shell dumpsys netstats | grep -E 'iface=wlan.*networkId'
def _getnetwork(device):
    (rc, out, err) = _adb(['shell', 'dumpsys netstats | grep -E "iface=wlan.*networkId"'], device=device)
    print(('network done ' + str(rc)))
    if rc != 0:
        print(err)

    # Decode the output from bytes to string
    out_str = out.decode('utf-8')
    # print(out_str)  # Print the output for debugging purposes

    network = {
        'connected': False,
        'ssid': 'unknown'
    }

    # Split the output by lines and iterate over each line
    for line in out_str.split('\n'):
        # Check if the line contains the network information we're interested in
        if 'iface=wlan' in line and 'networkId' in line:
            tokens = line.split(',')
            for token in tokens:
                if 'networkId=' in token:
                    network['ssid'] = token.split('=')[1].strip('" ')
                    break
            network['connected'] = True  # Assuming presence of 'networkId' indicates connected state
            break  # Exit the loop once network info is found
    print(network)
    return network



def _getbattery(device):
    (rc, out, err) = _adb(['shell', 'dumpsys', 'battery'], device=device)
    print(('battery done ' + str(rc)))
    if rc != 0:
        print(err)

    battery = {
        'plugged': 0,
        'level': 0,
        'status': 1,
        'health': 1
    }

    for l in out.decode('utf-8').split('\n'):
        tokens = l.split(': ')
        if len(tokens) < 2:
            continue

        key = tokens[0].strip().lower()
        value = tokens[1].strip().lower()
        if key == 'ac powered' and value == 'true':
            battery['plugged'] = 'AC'
        elif  key == 'usb powered' and value == 'true':
            battery['plugged'] = 'USB'
        elif  key == 'wireless powered' and value == 'true':
            battery['plugged'] = 'Wireless'
        elif  key == 'level':
            battery['level'] = value
        elif  key == 'status':
            battery['status'] = value
        elif  key == 'health':
            battery['health'] = value
    # print(battery)
    return battery

def _getscreen(device):
    (rc, out, err) = _adb(['shell', 'dumpsys', 'input'], device=device)
    print(('screen done ' + str(rc)))
    if rc != 0:
        print(err)

    screen = {
        'width': 0,
        'height': 0,
        'orientation': 0,
        'density': 0
    }

    for l in out.decode('utf-8').split('\n'):
        tokens = l.split(': ')
        if len(tokens) < 2:
            continue

        key = tokens[0].strip().lower()
        value = tokens[1].strip().lower()
        if  key == 'surfacewidth':
            screen['width'] = value
        elif  key == 'surfaceheight':
            screen['height'] = value
        elif  key == 'surfaceorientation':
            screen['orientation'] = value

    (rc, out, err) = _adb(['shell', 'wm', 'density'], device=device)
    tokens = out.decode('utf-8').split(': ')
    if len(tokens) == 2:
        screen['density'] = tokens[1].strip()

    return screen

def get_devices(handler):
    (_, out, _) = _adb(['devices'])
    devices = []
    for l in out.decode('utf-8').split('\n'):
        tokens = l.split()
        if not len(tokens) == 2:
            # Discard line that doesn't contain device information
            continue

        id = tokens[0]
        devices.append({
            'id': id,
            'manufacturer': _getprop(id, 'ro.product.manufacturer', 'unknown'),
            'model': _getprop(id, 'ro.product.model', 'unknown'),
            'sdk': _getprop(id, 'ro.build.version.sdk', 'unknown'),
            'network': _getnetwork(id),
            'battery': _getbattery(id),
            'screen': _getscreen(id)
        })

    return devices

def get_screenshot(handler):
    path = urlparse(handler.path).path
    device = path[12:]
    print(device)
    (rc, out, err) = _adb(['exec-out', 'screencap', '-p'], device=device)
    print(('screencap done ' + str(rc)))
    if rc != 0:
        print(err)
    return out

def get_logcat(handler):
    path = urlparse(handler.path).path
    device = path[8:]
    print(device)
    (rc, out, err) = _adb(['logcat', '-d', '-v', 'brief'], device=device)
    print(('logcat done ' + str(rc)))
    if rc != 0:
        print(err)
    return out

def get_info(handler):
    path = urlparse(handler.path).path
    device = path[9:]
    print(device)

    info = {
        'id': device,
        'manufacturer': 'unknown',
        'model': 'unknown',
        'sdk': 'unknown',
        'network': _getnetwork(device),
        'battery': _getbattery(device),
        'screen': _getscreen(device)
    }
    
    manufacturer = _getprop(device, 'ro.product.manufacturer', None)
    if manufacturer is not None:
        info['manufacturer'] = manufacturer

    model = _getprop(device, 'ro.product.model', None)
    if model is not None:
        info['model'] = model

    sdk = _getprop(device, 'ro.build.version.sdk', None)
    if sdk is not None:
        info['sdk'] = sdk

    return info


def post_key(handler):
    payload = handler.get_payload()
    if 'device' in payload and 'key' in payload:
        device = payload['device']
        key = payload['key']
        print((device + ' : ' + str(key)))
        (rc, _, err) = _adb(['shell', 'input', 'keyevent', key], device=device)
        print(('keyevent done ' + str(rc)))
        if rc != 0:
            print(err)
    return 'OK'

def post_text(handler):
    payload = handler.get_payload()
    if 'device' in payload and 'text' in payload:
        device = payload['device']
        text = payload['text']
        text = text.replace(' ', '%s')
        print((device + ' : ' + str(text)))
        (rc, _, err) = _adb(['shell', 'input', 'text', '"' + text + '"'], device=device)
        print(('text done ' + str(rc)))
        if rc != 0:
            print(err)
    return 'OK'

def post_tap(handler):
    payload = handler.get_payload()
    if 'device' in payload and 'x' in payload and 'y' in payload:
        device = payload['device']
        x = payload['x']
        y = payload['y']
        print((device + ' : ' + str(x) + ', ' + str(y)))
        (rc, _, err) = _adb(['shell', 'input', 'tap', x, y], device=device)
        print(('tap done ' + str(rc)))
        if rc != 0:
            print(err)
    return 'OK'

def post_shell(handler):
    payload = handler.get_payload()
    if 'device' in payload and 'command' in payload:
        device = payload['device']
        command = payload['command']
        print((device + ' : ' + command))
        (rc, out, err) = _adb(['shell', command], device=device)
        print(('shell done ' + str(rc)))
        if rc != 0:
            print(err)
    return out

def post_reboot(handler):
    payload = handler.get_payload()
    if 'device' in payload:
        device = payload['device']
        print(device)
        (rc, _, err) = _adb(['reboot'], device=device)
        print(('reboot done ' + str(rc)))
        if rc != 0:
            print(err)
    return 'OK'

def post_scrcpy(handler):
    payload = handler.get_payload()
    if 'device' in payload:
        device = payload['device']
        (_, _, _) = _scrcpy(device=device)
        return 'OK'
    else:
        return 'Device not specified'

def _scrcpy(device=None):
    # Adjust this path to the location of the scrcpy binary on your system
    scrcpy_path = 'C:/ProgramData/chocolatey/lib/scrcpy/tools/scrcpy.exe'  

    command = [scrcpy_path]
    if device is not None:
        command.extend(['-s', device])

    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return (p.returncode, stdout, stderr)

def _pair(ip_port, verification_code):
    command = ['pair', ip_port, verification_code]
    return _adb(command)

def post_pair(handler):
    payload = handler.get_payload()
    if 'ipPort' in payload and 'verificationCode' in payload:
        ip_port = payload['ipPort']
        verification_code = payload['verificationCode']
        output = _pair(ip_port, verification_code)
        return output
    else:
        return 'Invalid request parameters'
def _connectDevice(ip_port):
    command = ['connect', ip_port]
    return _adb(command)

def post_connectDevice(handler):
    payload = handler.get_payload()
    if 'ipPort' in payload:
        ip_port = payload['ipPort']
        output = _connectDevice(ip_port)
        return output
    else:
        return 'Invalid request parameters' 

def _deletepkg(device, pkg):
    command = ['uninstall', pkg]
    result = _adb(command, device)
    if result[0] == 0 and "Success" in result[1].decode('utf-8'):
        print(f"{pkg} deleted successfully.")
    else:
        print(f"Error deleting {pkg}: {result[1].decode('utf-8')}")

def post_deletepkg(handler):
    payload = handler.get_payload()
    if 'device' in payload and 'pkg' in payload:
        device = payload['device']
        pkg = payload['pkg']
        _deletepkg(device, pkg)
        return f"Deleted package {pkg} on device {device}"
    else:
        return 'Invalid request parameters'

def open_cmd_handler(device=None):
    # Execute the batch script with the provided device ID
    subprocess.Popen(['web\\open_cmd.bat', device], stdout=subprocess.PIPE)
    # Respond to the client indicating success or failure

def open_cmd(handler):
    payload = handler.get_payload()
    if 'device' in payload:
        device = payload['device']
        (_, _, _) = open_cmd_handler(device=device)
        return 'OK'
    else:
        return 'Device not specified'

# def n_analysis(handler):
#     payload = handler.get_payload()
#     if 'device' in payload:
#         device = payload['device']
#         command = "tcpdump -i any -s 0 -w - -nnvvv -C 100 -W 10 -Z root | pv -b > /sdcard/capture.pcap"
#         print((device + ' : ' + command))
#         (rc, out, err) = _adb(['shell', command], device=device)
#         print(('shell done ' + str(rc)))
#         if rc != 0:
#             print(err)
#     return out


def r_device(handler):
    payload = handler.get_payload()
    if 'device' in payload:
        device_id = payload['device']
        # Remove the device from the devices array
        # devices[:] = [d for d in devices if d['id'] != device_id]
        return f"Device {device_id} removed successfully"
    else:
        return 'Invalid request parameters'
    
def netidata(handler):
    payload = handler.get_payload()
    if 'device' in payload :
        command = payload['command']
        # print((device + ' : ' + command))
        (rc, out, err) = _adb(['shell', command])
        print(('shell done ' + str(rc)))
        if rc != 0:
            print(err)
            return err  # Return error message if ADB command execution fails
        else:
            return out.decode('utf-8')  # Return the output of the ADB command as a string
    else:
        return 'Invalid request parameters'  # Return error messa

def onAndoff(handler):
    payload = handler.get_payload()
    if 'device' in payload and 'command' in payload:
        device = payload['device']
        command = payload['command']
        print((device + ' : ' + command))
        (rc, out, err) = _adb(['shell', command], device=device)
        print(('shell done ' + str(rc)))
        if rc != 0:
            print(err)
    return out

class RESTRequestHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.routes = {
            r'^/$': {'file': 'web/idx.html', 'media_type': 'text/html'},
            r'^/full$': {'file': 'web/index.html', 'media_type': 'text/html'},
            r'^/devices$': {'GET': get_devices, 'media_type': 'application/json'},
            r'^/screenshot': {'GET': get_screenshot, 'media_type': 'image/png', 'cache_type': 'no-cache, no-store, must-revalidate'},
            r'^/logcat': {'GET': get_logcat, 'media_type': 'text/plain'},
            r'^/info': {'GET': get_info, 'media_type': 'application/json'},
            r'^/key$': {'POST': post_key, 'media_type': 'text/plain'},
            r'^/text$': {'POST': post_text, 'media_type': 'text/plain'},
            r'^/tap$': {'POST': post_tap, 'media_type': 'text/plain'},
            r'^/shell$': {'POST': post_shell, 'media_type': 'text/plain'},
            r'^/reboot$': {'POST': post_reboot, 'media_type': 'text/plain'},
            r'^/scrcpy$': {'POST': post_scrcpy, 'media_type': 'text/plain'},
            r'^/pair$': {'POST': post_pair, 'media_type': 'text/plain'},
             r'^/connect$': {'POST': post_connectDevice, 'media_type': 'text/plain'},
             r'^/deletepkg$': {'POST': post_deletepkg, 'media_type': 'text/plain'},
             r'^/open_cmd$': {'POST': open_cmd, 'media_type': 'text/plain'},
            #  r'^/netan$': {'POST': n_analysis, 'media_type': 'text/plain'},
             r'^/remove_device$': {'POST': r_device, 'media_type': 'text/plain'},
             r'^/netdata$': {'POST': netidata, 'media_type': 'text/plain'},
             r'^/onOff$': {'POST': onAndoff, 'media_type': 'text/plain'}
        }

        return http.server.BaseHTTPRequestHandler.__init__(self, *args, **kwargs)
    
    def do_HEAD(self):
        self.handle_method('HEAD')
    
    def do_GET(self):
        self.handle_method('GET')

    def do_POST(self):
        self.handle_method('POST')

    def do_PUT(self):
        self.handle_method('PUT')

    def do_DELETE(self):
        self.handle_method('DELETE')
    
    def get_payload(self):
        payload_len = int(self.headers.get('content-length', 0))
        payload = self.rfile.read(payload_len)
        payload = json.loads(payload)
        return payload
        
    def handle_method(self, method):
        route = self.get_route()
        if route is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write('Route not found\n'.encode())
        else:
            if method == 'HEAD':
                self.send_response(200)
                if 'media_type' in route:
                    self.send_header('Content-type', route['media_type'])
                self.end_headers()
            else:
                if 'file' in route and method == 'GET':
                    try:
                        here = os.path.dirname(os.path.realpath(__file__))
                        f = open(os.path.join(here, route['file']))
                        try:
                            self.send_response(200)
                            if 'media_type' in route:
                                self.send_header('Content-type', route['media_type'])
                            self.end_headers()
                            self.wfile.write(f.read().encode())
                        finally:
                            f.close()
                    except:
                        self.send_response(404)
                        self.end_headers()
                        self.wfile.write('File not found\n')
                else:
                    if method in route:
                        content = route[method](self)
                        if content is not None:
                            self.send_response(200)
                            if 'media_type' in route:
                                self.send_header('Content-type', route['media_type'])
                            if 'cache_type' in route:
                                self.send_header('Cache-control', route['cache_type'])
                            self.end_headers()
                            if method != 'DELETE':
                                if route['media_type'] == 'application/json':
                                    self.wfile.write(json.dumps(content).encode())
                                else:
                                    self.wfile.write(content)
                        else:
                            self.send_response(404)
                            self.end_headers()
                            self.wfile.write('Not found\n')
                    else:
                        self.send_response(405)
                        self.end_headers()
                        self.wfile.write(method + ' is not supported\n')
                        
    def get_route(self):
        for path, route in self.routes.items():
            if re.match(path, self.path):
                return route
        return None

def rest_server(port):
    http_server = http.server.HTTPServer(('', port), RESTRequestHandler)
    if arguments.certfile:
        http_server.socket = ssl.wrap_socket(http_server.socket, certfile=arguments.certfile, server_side=True)

    print(('Starting HTTP server at port %d' % port))

    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        pass

    print('Stopping HTTP server')
    http_server.server_close()

if __name__ == '__main__':
    rest_server(arguments.port)