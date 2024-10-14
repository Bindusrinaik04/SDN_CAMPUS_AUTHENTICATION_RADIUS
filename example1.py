#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call
from mininet.util import irange

def myNetwork():
    # Cleanup existing Mininet instances and interfaces
    for i in irange(0, 4):
        call(["mn", "-c"])  # Rest of your existing code...

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c1=net.addController(name='c1',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)

    info( '*** Add hosts\n')
    h5 = net.addHost('h5', cls=Host, ip='10.0.0.5', defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.13', defaultRoute=None)
    h6 = net.addHost('h6', cls=Host, ip='10.0.0.21', defaultRoute=None)
    h4 = net.addHost('h4', cls=Host, ip='10.0.0.15', defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.12', defaultRoute=None)
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.11', defaultRoute=None)

    info( '*** Add links\n')
    net.addLink(s1, h1)
    net.addLink(s1, h2)
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s3, s4)
    net.addLink(s2, h3)
    net.addLink(s3, h3)
    net.addLink(s3, h4)
    net.addLink(s4, h5)
    net.addLink(s4, h6)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s4').start([c0])
    net.get('s3').start([c1,c0])
    net.get('s1').start([c1])
    net.get('s2').start([c1])
    info( '*** Post configure switches and hosts\n')
    s4.cmd('ifconfig s4 10.0.0.4')
    s3.cmd('ifconfig s3 10.0.0.3')
    s1.cmd('ifconfig s1 10.0.0.1')
    s2.cmd('ifconfig s2 10.0.0.2')
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()
