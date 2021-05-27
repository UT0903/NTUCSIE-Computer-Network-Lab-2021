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

from operator import attrgetter

from ryu.app import simple_switch_stp_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

from ryu.base import app_manager

from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, arp, tcp, udp, icmp
from ryu.ofproto import inet
from subprocess import call
import numpy as np
from new_stp import SimpleSwitch13
# from temp_stp import SimpleSwitch13


class SimpleMonitor13(SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.record = {}
        self.shutdown = None

    def disable_port(self, dpid, port_no, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        hw_addr = self.stp.bridge_list[dpid].ports[port_no].ofport.hw_addr
        config = ofp.OFPPC_PORT_DOWN
        mask = ofp.OFPPC_PORT_DOWN
        advertise = 0
        req = ofp_parser.OFPPortMod(datapath, port_no, hw_addr, config, mask, advertise)
        datapath.send_msg(req)

        if self.shutdown:
            return
        interface = "s{}-eth{}".format(dpid, port_no)
        self.logger.info("kick dpid=[%d] port=[%d]", dpid, port_no)
        self.logger.info("shuwdown link %s", interface)
        self.logger.info('###\n###\n###\n')
        call(["sudo", "ifconfig", interface, "down"])
        self.shutdown = interface

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        #for key, value in ev.msg.iteritems():
        #    self.logger.info('ev.msg: %s %s', key, value)
        if dpid not in self.record:
            self.record[dpid] = {}

        '''
        sort_list : flow table in datapath
        grow_list : transmit amount in past 10 second
        group_dict : (key -> out_port : value-> list(index in sort list) )
        new record : (key -> (in_port, out_port) : value -> transmit amount)
        '''
        # print 'body', body
        sort_list = sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst']))
        #self.logger.info('---------------------------------------------')
        
        #self.logger.info('---------------------------------------------')
        grow_list = []
        group_dict = {}
        new_record = {}

        print('datapath         in-port  match src_ip src_port         dst_ip dst_port protocol  action  packets  bytes')
        print('---------------- -------- --------------------------------------------- --------- ------- -------- --------')
        for e, stat in enumerate(sort_list):
            action = ' '
            if 'ip_proto' not in stat.match:
                print('no ip_proto')
                continue
            global src_port
            global dst_port
            global protocol
            src_port = -1
            dst_port = -1
            protocol = 'ICMP'
            if stat.match['ip_proto'] == inet.IPPROTO_TCP:
                src_port = stat.match['tcp_src']
                dst_port = stat.match['tcp_dst']
                protocol = 'TCP'
            elif stat.match['ip_proto'] == inet.IPPROTO_UDP:
                src_port = stat.match['udp_src']
                dst_port = stat.match['udp_dst']
                protocol = 'UDP'
                    
            
            print('%016x %8d %16s %8d %16s %8d %9s %7s %8d %8d' % (
                ev.msg.datapath.id, stat.match['in_port'], stat.match['ipv4_src'], src_port,
                stat.match['ipv4_dst'], dst_port, protocol, action, stat.packet_count, stat.byte_count))
        
        # self.logger.info('datapath       '
        #                  'ipv4_src         ipv4_dst         in-port  eth-dst           '
        #                  'out-port packets  bytes')
        
        # for e, stat in enumerate(sort_list):
        #     self.logger.info('%016x %16s %16s %8x %17s %8x %8d %8d',
        #                      ev.msg.datapath.id,
        #                      stat.match['ipv4_src'], stat.match['ipv4_dst'],
        #                      stat.match['in_port'], stat.match['eth_dst'],
        #                      stat.instructions[0].actions[0].port,
        #                      stat.packet_count, stat.byte_count)

            trans_amount = stat.byte_count
            in_port = stat.match['in_port']
            if not stat.instructions:
                continue
            out_port = stat.instructions[0].actions[0].port
            if in_port == out_port:
                continue
            key = (in_port, out_port)
            new_record[key] = trans_amount

            ### detect if transfering packet
            if key in self.record[dpid]:
                old_trans_amount = self.record[dpid][key]
                grow = trans_amount-old_trans_amount
            else:
                grow = trans_amount
            grow_list.append(grow)

            ### group different in_port with same out_port
            if out_port == 1: # reach destination
                continue
            elif out_port not in group_dict:
                group_dict[out_port] = [e]
            else:
                group_dict[out_port].append(e)

        ### detect congestion
        for group_key in group_dict:
            group = group_dict[group_key]
            if len(group) == 1:
                # print('fuck')
                continue
            
            group_grow_list = [grow_list[i] for i in group]
            order = np.argsort(group_grow_list)[::-1]
            growsum = np.sum(group_grow_list)
            self.logger.info("growsum = %d", growsum)
            threshold = 1000000
            if growsum <= threshold:
                # for group_idx in order:
                #     stat = sort_list[group[group_idx]]
                #     grow = group_grow_list[group_idx]
                #     in_port = stat.match['in_port']
                #     out_port = stat.instructions[0].actions[0].port
                #     self.logger.info("in_port = %8x, growsum = %d", in_port, growsum)

                #     # self.disable_port(dpid, in_port, ev.msg.datapath)

                #     self.logger.info("###\n###\nNo congestion, delete rule of drop packet")
                #     self.drop_packet(dpid, in_port, ev.msg.datapath)
                #     break
                continue
            else:
                for group_idx in order:
                    stat = sort_list[group[group_idx]]
                    grow = group_grow_list[group_idx]
                    in_port = stat.match['in_port']
                    out_port = stat.instructions[0].actions[0].port
                    self.logger.info("in_port = %8x, growsum = %d", in_port, growsum)

                    # self.disable_port(dpid, in_port, ev.msg.datapath)

                    self.logger.info("###\n###\nCongestion detected ! List all congestion flow")
                    
                    datapath = ev.msg.datapath
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser
                    
                    match = parser.OFPMatch(eth_type = 0x0800)
                    if stat.match['ip_proto'] == inet.IPPROTO_TCP:
                        match = parser.OFPMatch(eth_type = 0x0800, 
                                                # in_port=stat.match['in_port'], 
                                                # eth_dst=stat.match['eth_dst'],
                                                ipv4_dst=stat.match['ipv4_dst'], 
                                                ipv4_src=stat.match['ipv4_src'], 
                                                ip_proto=stat.match['ip_proto'])#, 
                                                #tcp_src=stat.match['tcp_src'], 
                                                #tcp_dst=stat.match['tcp_dst'])
                    elif stat.match['ip_proto'] == inet.IPPROTO_UDP:
                        match = parser.OFPMatch(eth_type = 0x0800, 
                                                ipv4_dst=stat.match['ipv4_dst'], 
                                                ipv4_src=stat.match['ipv4_src'], 
                                                ip_proto=stat.match['ip_proto'])#, 
                                                #udp_src=stat.match['udp_src'], 
                                                #udp_dst=stat.match['udp_dst'])
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
                    mod = parser.OFPFlowMod(datapath=datapath, priority=2,
                                            match=match, instructions=inst)
                    datapath.send_msg(mod)
                    
                    '''
                    instruction = [
                        parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])
                    ]
                    msg = parser.OFPFlowMod(datapath,
                                            #table_id = OFDPA_FLOW_TABLE_ID_ACL_POLICY,
                                            priority = 2,
                                            command = ofproto.OFPFC_ADD,
                                            match = match,
                                            instructions = instruction
                                            )
                    #self._log("dropEthType : %s" % str(msg))
                    reply = datapath.send_msg(msg)
                    '''
                    print "drop packet"
                    
                    break

            self.logger.info("###\n###\n")
       

        ### update record
        for key in new_record:
            self.record[dpid][key] = new_record[key]

    def clear_drop_rule(self, dpid, in_port, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type = 0x0800)
        instruction = [
            parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])
            ]
        msg = parser.OFPFlowMod(datapath,
                                #table_id = OFDPA_FLOW_TABLE_ID_ACL_POLICY,
                                priority = 2,
                                command = ofproto.OFPFC_DELETE,
                                match = match,
                                instructions = instruction
                                )
        #self._log("dropEthType : %s" % str(msg))
        reply = datapath.send_msg(msg)
        print "drop packet"
        if reply:
            raise Exception
    
    def drop_packet(self, dpid, in_port, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type = 0x0800)
        instruction = [
            parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])
            ]
        msg = parser.OFPFlowMod(datapath,
                                #table_id = OFDPA_FLOW_TABLE_ID_ACL_POLICY,
                                priority = 2,
                                command = ofproto.OFPFC_ADD,
                                match = match,
                                instructions = instruction
                                )
        #self._log("dropEthType : %s" % str(msg))
        reply = datapath.send_msg(msg)
        print "drop packet"
        if reply:
            raise Exception

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)
