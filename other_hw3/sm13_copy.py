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

# from new_stp import SimpleSwitch13
from ryu.app import simple_switch_stp_13

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub


# class SimpleMonitor13(SimpleSwitch13):
class SimpleMonitor13(simple_switch_stp_13.SimpleSwitch13):

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

        if dpid not in self.record:
            self.record[dpid] = {}

        '''
        sort_list : flow table in datapath
        grow_list : transmit amount in past 10 second
        group_dict : (key -> out_port : value-> list(index in sort list) )
        new record : (key -> (in_port, out_port) : value -> transmit amount)
        '''

        grow_list = []
        group_dict = {}
        new_record = {}


        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

            trans_amount = stat.byte_count
            in_port = stat.match['in_port']
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
                continue
            
            group_grow_list = [grow_list[i] for i in group]
            order = np.argsort(group_grow_list)[::-1]
            growsum = np.sum(group_grow_list)

            threshold = 1000000
            if growsum <= threshold:
                continue
            

            for group_idx in order:
                stat = sort_list[group[group_idx]]
                grow = group_grow_list[group_idx]
                in_port = stat.match['in_port']
                out_port = stat.instructions[0].actions[0].port
                if in_port != 1:
                    self.disable_port(dpid, in_port, ev.msg.datapath)

                    self.logger.info("###\n###\nCongestion detected ! List all congestion flow")
                    self.logger.info('datapath         '
                             'in-port  eth-dst           '
                             'out-port grow')
                    self.logger.info('---------------- '
                             '-------- ----------------- '
                             '-------- --------')

                    for group_idx in order:
                        stat = sort_list[group[group_idx]]
                        grow = group_grow_list[group_idx]
                        self.logger.info('%016x %8x %17s %8x %8d',
                                     ev.msg.datapath.id,
                                     stat.match['in_port'], stat.match['eth_dst'],
                                     stat.instructions[0].actions[0].port,
                                     grow)
                    break

            self.logger.info("###\n###\n")
       

        ### update record
        for key in new_record:
            self.record[dpid][key] = new_record[key]


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
