from mininet.topo import Topo
class MyTopo (Topo):
    def __init__(self ):
        Topo.__init__(self)
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')
        host5 = self.addHost('h5')
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')
        switch4 = self.addSwitch('s4')
        self.addLink(switch1, switch2)
        self.addLink(switch1, switch3)
        self.addLink(switch1, switch4)
        self.addLink(host1, switch2)
        self.addLink(host2, switch2)
        self.addLink(host3, switch3)
        self.addLink(host4, switch3)
        self.addLink(host5, switch4)
        # self.addLink(leftHost,leftSwitch)
        # self.addLink(leftSwitch,rightSwitch) 
        # self.addLink(rightSwitch,rightHost)

topos = {'mytopo':(lambda: MyTopo())}