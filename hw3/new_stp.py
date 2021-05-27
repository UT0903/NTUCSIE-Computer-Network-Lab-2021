# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, arp, tcp, udp, icmp
from ryu.app import simple_switch_13
from ryu.ofproto import inet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto

class SimpleSwitch13(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stp = kwargs['stplib']

        # Sample of stplib config.
        #  please refer to stplib.Stp.set_config() for details.
        config = {dpid_lib.str_to_dpid('0000000000000001'):
                  {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000003'):
                  {'bridge': {'priority': 0xa000}}}
        self.stp.set_config(config)
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)
    #@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    
    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)

        dst = eth.dst
        src = eth.src

        # src_ip = "1.1.1.1"
        # dst_ip = "2.2.2.2"
        # ip_proto = 6
        # match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
        # if arp_pkt:
        #     self.logger.info('---------------------------------------------')
        #     print "enter arp_pkt"
        #     self.logger.info('---------------------------------------------')
        #     src_ip = arp_pkt.src_ip
        #     dst_ip = arp_pkt.dst_ip
        #     #eth_type = arp_pkt.eth_type
        #     match = parser.OFPMatch(in_port=in_port,  
        #                             eth_dst=dst)
        # elif ip_pkt:
        #     src_ip = ip_pkt.src
        #     dst_ip = ip_pkt.dst
        #     #eth_type = ip_pkt.eth_type
        #     self.logger.info('---------------------------------------------')
        #     print "enter ip_pkt"
        #     self.logger.info('---------------------------------------------')
        #     if pkt_tcp:
        #         self.logger.info('---------------------------------------------')
        #         print "enter tcp_pkt"
        #         self.logger.info('---------------------------------------------')
        #         tcp_src = pkt_tcp.src_port
        #         tcp_dst = pkt_tcp.dst_port
        #         ip_proto = inet.IPPROTO_TCP
        #         match = parser.OFPMatch(in_port=in_port, 
        #                                 eth_type=0x8000, 
        #                                 eth_dst=dst,
        #                                 ip_proto=6, 
        #                                 ipv4_src=src_ip, 
        #                                 ipv4_dst=dst_ip, 
        #                                 tcp_src=tcp_src,
        #                                 tcp_dst=tcp_dst)
        #     elif pkt_udp:
        #         self.logger.info('---------------------------------------------')
        #         print "enter udp_pkt"
        #         self.logger.info('---------------------------------------------')
        #         ip_proto = inet.IPPROTO_UDP
        #         udp_src = pkt_udp.src_port
        #         udp_dst = pkt_udp.dst_port
        #         match = parser.OFPMatch(in_port=in_port, 
        #                                 eth_type=0x8000, 
        #                                 eth_dst=dst,
        #                                 ip_proto=17,  
        #                                 ipv4_src=src_ip, 
        #                                 ipv4_dst=dst_ip,
        #                                 udp_src=udp_src,
        #                                 udp_dst=udp_dst)
        #     elif pkt_icmp:
        #         self.logger.info('---------------------------------------------')
        #         print "enter icmp_pkt"
        #         self.logger.info('---------------------------------------------')
        #         ip_proto = inet.IPPROTO_ICMP
        #         match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x8000, ip_proto=1, ipv4_src=src_ip, ipv4_dst=dst_ip)
        #     print 'match', match["ip_proto"], match["ipv4_src"], match["ipv4_dst"] 
        # else:
            # src_ip = eth_pkt.src
            # dst_ip = eth_pkt.dst
        #self.logger.info("src_ip=%s, dst_ip=%s", src_ip, dst_ip)
        #print(src_ip)


        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        #print(msg)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        '''
        if arp_pkt or ip_pkt:
            if int(src_ip.split(".")[-1]) % 2 != int(dst_ip.split(".")[-1]) % 2:
                actions = [parser.OFPActionOutput(out_port)]
                #self.logger.info("drop")
            else:
                actions = [parser.OFPActionOutput(out_port)]
                #self.logger.info("don't drop")
        else:
        '''
        actions = [parser.OFPActionOutput(out_port)]
        
            #self.logger.info("don't care")
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                if int(srcip.split(".")[-1]) % 2 != int(dstip.split(".")[-1]) % 2:
                    actions = []
                #self.logger.info("drop")
                else:
                    actions = [parser.OFPActionOutput(out_port)]
                    #self.logger.info("don't drop")
                protocol = ip.proto
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=srcip,
                                ipv4_dst=dstip
                                )
                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, in_port=in_port, eth_dst=dst)
            
                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port,in_port=in_port, eth_dst=dst)
            
                #  If UDP Protocol 
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port,in_port=in_port, eth_dst=dst)            

                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            '''
            if arp_pkt or ip_pkt:
                match = parser.OFPMatch(in_port=in_port, eth_type=0x8000, ip_proto=6, eth_dst=dst, ipv4_src=src_ip, ipv4_dst=dst_ip)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            '''
            # print "----------1231--------------------"
            # if "ip_proto" in match:
            #     print match["ip_proto"], match["ipv4_src"], match["ipv4_dst"] 
            # else:
            #     print "no proto"
            # print "----------1231--------------------"
            # if not arp_pkt:
            #     self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        # self.logger.debug("[dpid=%s][port=%d] state=%s",
        #                   dpid_str, ev.port_no, of_state[ev.port_state])
