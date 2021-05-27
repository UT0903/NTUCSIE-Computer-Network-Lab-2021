from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.topo import Topo
class data_center(Topo):
    def __init__(self, core_num, pod_num):
        super(data_center,self).__init__()
 
        #Marking the number of switch for per level
        L1 = core_num
        L2 = pod_num*2
        L3 = L2
        host = L2*2
 
        #Starting create the switch
        c = []    #core switch
        a = []    #aggregate switch
        e = []    #edge switch
        h = []
        
        #notice: switch label is a special data structure
        for i in range(L1):
            c.append(self.addSwitch('c{}'.format(i)))
        for i in range(L2):
            a.append(self.addSwitch('a{}'.format(i+L1)))
        for i in range(L3):
            e.append(self.addSwitch('e{}'.format(i+L1+L2)))
        for i in range(host):
            h.append(self.addHost('h{}'.format(i+L1+L2+L3)))
        for i in range(len(c)):
            for j in range(len(a)):
                if i % 2 == j % 2:
                    self.addLink(c[i], a[j])
        for i in range(0, len(a), 2):
            self.addLink(e[i], a[i])
            self.addLink(e[i], a[i+1])
            self.addLink(e[i+1], a[i+1])
            self.addLink(e[i+1], a[i])
        for i in range(len(e)):
            self.addLink(e[i], h[2*i])
            self.addLink(e[i], h[2*i+1])

topos = {"data_center":(lambda:data_center(int(input('core_num:')), int(input('pod_num:'))))}