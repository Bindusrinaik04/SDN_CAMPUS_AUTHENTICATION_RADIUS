from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid, str_to_bool
from pox.lib.addresses import IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from bottle import Bottle, request, run,redirect
import threading
import time
import logging
import json
import socket
import subprocess
import requests
import sys
sys.path.append('./pox/pox/forwarding/')
from auth_db import AuthDB, cleanup_task


log = core.getLogger()
app = Bottle()
_flood_delay = 0
l2_instance=None
# Initialize the AuthDB
auth_db = AuthDB()


class LearningSwitch(object):
    def __init__(self, connection, transparent):
        self.connection = connection
        self.transparent = transparent
        self.macToPort = {}
        connection.addListeners(self)
        self.hold_down_expired = _flood_delay == 0

    def _handle_PacketIn(self, event):
        packet = event.parsed

        def flood(message=None):
            msg = of.ofp_packet_out()
            if time.time() - self.connection.connect_time >= _flood_delay:
                if not self.hold_down_expired:
                    self.hold_down_expired = True
                    log.info("%s: Flood hold-down expired -- flooding", dpid_to_str(event.dpid))
                if message is not None:
                    log.debug(message)
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)
        def drop(duration=None):
            if duration is not None:
                if not isinstance(duration, tuple):
                    duration = (duration, duration)
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet)
                msg.idle_timeout = duration[0]
                msg.hard_timeout = duration[1]
                msg.buffer_id = event.ofp.buffer_id
                self.connection.send(msg)
            elif event.ofp.buffer_id is not None:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                self.connection.send(msg)

        self.macToPort[packet.src] = event.port
        if not self.transparent:
            if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
                drop()
                return
        if packet.dst.is_multicast:
            flood()
        else:
            if packet.dst not in self.macToPort:
                flood("Port for %s unknown -- flooding" % (packet.dst,))
            else:
                port = self.macToPort[packet.dst]
                if port == event.port:
                    log.warning("Same port for packet from %s -> %s on %s.%s. Drop.",
                                packet.src, packet.dst, dpid_to_str(event.dpid), port)
                    drop(10)
                    return
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet, event.port)
                msg.idle_timeout = 10
                msg.hard_timeout = 30
                msg.actions.append(of.ofp_action_output(port=port))
                msg.data = event.ofp
                self.connection.send(msg)

class l2_learning(object):
    def __init__(self, transparent, ignore=None):
        core.openflow.addListeners(self)
        self.transparent = transparent
        self.ignore = set(ignore) if ignore else ()
        self.authenticated_clients = {}
    def _handle_ConnectionUp(self, event):
        if event.dpid in self.ignore:
            log.debug("Ignoring connection %s" % (event.connection,))
            return
        log.debug("Connection %s" % (event.connection,))
        LearningSwitch(event.connection, self.transparent)
        #self.install_eapol_flow(event.connection)
        self.install_http_capture_flow(event.connection)

    def install_http_capture_flow(self, connection):
        log.info("Installing HTTP capture flow")
        msg = of.ofp_flow_mod()
        msg.priority = 1000
        msg.match.dl_type = 0x0800
        msg.match.nw_proto = 6
        msg.match.tp_dst = 80
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        connection.send(msg)
        log.info("HTTP capture flow installed")

    def handle_packet_in(self, event):
        packet = event.parsed
        src_mac = str(packet.src)

        if not auth_db.is_authenticated(src_mac):
            self.redirect_to_web_interface(event)
        else:
            self.redirect_to_web_interface(event, packet)

    def redirect_to_web_interface(self, event):
        log.info("Redirecting to web interface")
        WEB_SERVER_IP = "192.168.72.37"
        WEB_SERVER_PORT = 8080
        eth = ethernet()
        eth.src = packet.dst
        eth.dst = packet.src
        eth.type = ethernet.IP_TYPE
        ip = ipv4()
        ip.srcip = packet.next.dstip
        ip.dstip = packet.next.srcip
        ip.protocol = ipv4.TCP_PROTOCOL
        tcp_packet = tcp()
        tcp_packet.srcport = packet.next.next.dstport
        tcp_packet.dstport = packet.next.next.srcport
        tcp_packet.flags = tcp.ACK
        tcp_packet.seq = packet.next.next.ack
        tcp_packet.ack = packet.next.next.seq + len(packet.next.next.payload)
        # http response
        http_response = (
            "HTTP/1.1 302 Found\r\n"
            "Location: http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/\r\n"
            "Content-Length: 0\r\n\r\n"
        ).format(WEB_SERVER_IP=WEB_SERVER_IP, WEB_SERVER_PORT=WEB_SERVER_PORT)
        tcp_packet.payload = http_response
        ip.payload = tcp_packet
        eth.payload = ip

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(msg)
        log.info("Redirection response sent to %s", packet.src)

    def forward_packet(self, event, packet):
        log.info("Forwarding packet normally")
        # Normal forwarding logic here

    def install_flow_for_authenticated_user(self, connection, ip):
        log.info("\n/**inside installing flow rules:Installing flow for authenticated user,ip: %s",ip)
        #log.info("Installing flow for authenticated user with IP: %s", ip)
        msg = of.ofp_flow_mod()
        msg.priority = 2000
        msg.match = of.ofp_match()
        msg.match.dl_type = 0x0800
        msg.match.nw_src = IPAddr(ip)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        
        connection.send(msg)
	log.info("flow installed for Ip:%s",ip)
     
def controller_socket_listener(): 
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((POX_CONTROLLER_IP, POX_CONTROLLER_PORT))
    server_socket.listen(5)
    log.info("Listening for authentication messages on %s:%s", POX_CONTROLLER_IP, POX_CONTROLLER_PORT)

    while True:
        client_socket, _ = server_socket.accept()
        try:
            message = client_socket.recv(1024)
            log.info("Received raw message: %s", message)
            message = message.decode('utf-8')
            data = json.loads(message)
            #log.info("Decoded message: %s", data)
            username = data.get('username')
            status = data.get('status')
	    ip=data.get('ip')
	    #session_time = request_json.get("session_time")
	    log.info("User authenticated: %s with IP: %s", username, ip)
            if username and status == 'authenticated':
                log.info("User authenticated: %s", username)
	        log.info("Active connections: %s", core.openflow._connections)
		auth_db.add_user(username, ip)
                for connection in core.openflow._connections.values():
		    log.info("Calling install_flow_for_authenticated_user for IP: %s on connection: %s", ip, connection)
                    l2_instance.install_flow_for_authenticated_user(connection,ip)

        except ValueError as e:
            log.error("Error decoding JSON message: %s", e)
        except Exception as e:
            log.error("Error processing authentication message: %s", e)
        finally:
            client_socket.close()
 
# Web application routes
RADIUS_SERVER = '192.168.72.164'
RADIUS_SECRET = 'secret'
RADIUS_AUTH_PORT = 1812

#client = Client(server=RADIUS_SERVER, secret=RADIUS_SECRET.encode(), dict=Dictionary("pox/radius_dictionary"))
#client.authport = RADIUS_AUTH_PORT

POX_CONTROLLER_IP = '127.0.0.1'  # Assuming POX controller is on the same machine
POX_CONTROLLER_PORT = 6650
@app.route('/')
def home():
    return ''' 
    <form action="/login" method="post">
        Username: <input name="username" type="text" />
        Password: <input name="password" type="password" />
        <input value="Login" type="submit" />
    </form>
    '''

@app.route('/login', method='POST')
def login():
    username = request.forms.get('username')
    password = request.forms.get('password')
    if auth_db.is_authenticated(username):
	return 'Already AUthenticated'
    else:
	auth_res = authenticate_with_radius(username, password)
    	response=auth_res[0]
    	ip=auth_res[1]
    	if response == 'Success':
            redirect_to_controller(username,ip)
        #redirect("/authenticate")
	    return "Authentication successful. Installing Flow."
        else:
            return "Authentication failed. Access denied."

import re
def authenticate_with_radius(username, password):
    try:
        # Use radtest command to authenticate with RADIUS server
        command = [
            'radtest', username, password, RADIUS_SERVER,
            '0', RADIUS_SECRET
        ]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
	'''command = 'radtest {} {} {} 0 {}'.format(username, password, RADIUS_SERVER_IP, RADIUS_SECRET)
        print("Executing command:", command)  # Debug statement
        result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result_output = result.communicate()
	'''
          # Debug statement
        result_output = stdout.decode('utf-8')
	print("RADIUS Command Output:", result_output)
        if "Access-Accept" in result_output:
	    match = re.search(r'Framed-IP-Address\s*=\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', result_output)
            framed_ip = match.group(1) if match else None
            return ['Success', framed_ip]
            #return 'Success'
        else:
            return ['Failure',None]
    except Exception as e:
        print("Error encountered with RADIUS server:", e)
        return 'Failure'

def redirect_to_controller(username,ip):
    message = {
        'username': username,
        'status': 'authenticated',
	'ip':ip
    }
    log.info("Sending message to pox controller :%s",message)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((POX_CONTROLLER_IP, POX_CONTROLLER_PORT))
        sock.sendall(json.dumps(message).encode('utf-8'))
        sock.close()
    except Exception as e:
        print("Error sending message to POX controller:", e)

'''@app.post('/authenticate')
def handle_authentication():
    global l2_instance
    try:
        data = request.json
        if data is None:
            raise ValueError("No JSON data received")
        
        username = data.get('username')
        status = data.get('status')
	ip=data.get('ip')
        if username and status == 'authenticated' and ip:
            l2_instance.authenticated_clients[username] = True
            log.info("inside authenticate page User authenticated: %s", username)
            for connection in core.openflow.connections:
                 if hasattr(connection, 'parent') and connection.parent:
                     connection.parent.authenticated_clients[username] = True
                     connection.parent.install_flow_for_authenticated_user(connection, username, ip)
            return HTTPResponse(status=200, body="Authentication status updated")
        else:
            return HTTPResponse(status=400, body="Invalid data")
    except ValueError as ve:
        log.error("JSON decode error: %s", ve)
        return HTTPResponse(status=400, body="Invalid JSON data")
    except Exception as e:
        log.error("Unexpected error: %s", e)
        return HTTPResponse(status=500, body="Internal server error")
'''
def run_web_server():
    run(app, host='0.0.0.0', port=8080)

def launch(transparent=False, hold_down=_flood_delay, ignore=None):
    global _flood_delay,l2_instance
    
    try:
        _flood_delay = int(str(hold_down), 10)
        assert _flood_delay >= 0
    except:
        raise RuntimeError("Expected hold-down to be a number")

    if ignore:
        ignore = ignore.replace(',', ' ').split()
        ignore = set(str_to_dpid(dpid) for dpid in ignore)
    
    l2_instance = l2_learning(str_to_bool(transparent), ignore)
    core.register("l2_learning", l2_instance)
    
    threading.Thread(target=run_web_server).start()
    threading.Thread(target=controller_socket_listener).start()
    threading.Thread(target=cleanup_task, args=(auth_db,)).start() 
    #core.registerNew(l2_learning, str_to_bool(transparent), ignore)
    #threading.Thread(target=run_web_server).start()
    #threading.Thread(target=l2_learning.controller_socket_listener).start()
     
 


