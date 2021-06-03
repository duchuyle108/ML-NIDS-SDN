
# A hand-tuned application collecting data samples for intrusion and normal traffic.

# Method: Periodically (can be set by modifying var 'interval' of 'collect_stats' class) collect 
#          the switch's flow statistics and accumulate data samples. 

# Note: + Run with my_forwarding component

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
from pox.lib.recoco import Timer
from pox.lib.packet.packet_utils import *
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp
from pox.lib.packet.icmp import icmp
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, parse_cidr

import time
from datetime import datetime
from random import randint

# Define local network IP range.
LOCAL_NETWORK = parse_cidr("10.0.0.0/24")
PROTOCOL_NAME = {ipv4.ICMP_PROTOCOL : 'icmp', ipv4.TCP_PROTOCOL : 'tcp', ipv4.UDP_PROTOCOL : 'udp'}
log = core.getLogger()

class collect_stats(object):
    def __init__ (self):
        self.connection = None
        self.interval = 1.2
        core.openflow.addListeners(self)

    # Function handle flow stats 
    def _handle_FlowStatsReceived (self, event):
        log.info("--------------------------------------------------------")
        log.info(datetime.now().strftime("%H:%M:%S"))
        flow_stats = event.stats
        file = open('data/tcpsynflood.txt','a+')
        log.info("Found " + str(len(flow_stats)) + " flows")

        # Re-arrange and extract some flow statistics value
        flow_info = {}
        active_hosts = []
        for flow in flow_stats:
            match = flow.match
            if match.nw_proto not in [ipv4.ICMP_PROTOCOL, ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL]:
                continue
            if match.nw_src not in active_hosts and match.nw_src.inNetwork(LOCAL_NETWORK) :
                active_hosts.append(match.nw_src)
            if match.nw_dst not in active_hosts and match.nw_dst.inNetwork(LOCAL_NETWORK):
                active_hosts.append(match.nw_dst)

            if match.nw_proto not in flow_info:
                flow_info[match.nw_proto] = {}
                flow_info[match.nw_proto][match.nw_src] = {}
                flow_info[match.nw_proto][match.nw_src][match.tp_src] = {}
                flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst] = {}
                flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst][match.tp_dst] = {}
                flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst][match.tp_dst]['packet_count'] = flow.packet_count
            elif match.nw_src not in flow_info[match.nw_proto]:
                flow_info[match.nw_proto][match.nw_src] = {}
                flow_info[match.nw_proto][match.nw_src][match.tp_src] = {}
                flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst] = {}
                flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst][match.tp_dst] = {}
                flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst][match.tp_dst]['packet_count'] = flow.packet_count
            elif match.tp_src not in flow_info[match.nw_proto][match.nw_src]:
                flow_info[match.nw_proto][match.nw_src][match.tp_src] = {}
                flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst] = {}
                flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst][match.tp_dst] = {}
                flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst][match.tp_dst]['packet_count'] = flow.packet_count
            elif match.nw_dst not in flow_info[match.nw_proto][match.nw_src][match.tp_src]:
                flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst] = {}
                flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst][match.tp_dst] = {}
                flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst][match.tp_dst]['packet_count'] = flow.packet_count
            elif match.tp_dst not in flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst]:
                flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst][match.tp_dst] = {}
                flow_info[match.nw_proto][match.nw_src][match.tp_src][match.nw_dst][match.tp_dst]['packet_count'] = flow.packet_count
        
        # Analyse flows and compute data sample attributes
        for flow in flow_stats:
            match = flow.match
            if not match.nw_src.inNetwork(LOCAL_NETWORK) and not match.nw_dst.inNetwork(LOCAL_NETWORK):
                continue
            if match.nw_proto not in [ipv4.ICMP_PROTOCOL, ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL]:
                continue
            protocol = PROTOCOL_NAME[match.nw_proto]
            log.info(protocol)
            transfer_rate = float(flow.packet_count) / (flow.duration_sec + float(flow.duration_nsec) /1e9) if (flow.duration_nsec != 0 and flow.duration_sec != 0) else 0

            average_packet_size = flow.byte_count / flow.packet_count if flow.packet_count != 0 else 0

            ssrc_sproto_nhosts = []
            for tpsrc in flow_info[match.nw_proto][match.nw_src]:
                for nwdst in flow_info[match.nw_proto][match.nw_src][tpsrc]:
                    if nwdst not in ssrc_sproto_nhosts and nwdst.inNetwork(LOCAL_NETWORK):
                        ssrc_sproto_nhosts.append(nwdst)
            ssrc_sproto_percentage_hosts = float(len(ssrc_sproto_nhosts)) / (len(active_hosts))
            
            ssrc_sproto_sdst_nflows = 0
            for tpsrc in flow_info[match.nw_proto][match.nw_src]:
                try:
                    ssrc_sproto_sdst_nflows += len(flow_info[match.nw_proto][match.nw_src][tpsrc][match.nw_dst])
                except KeyError:
                    pass
            try:
                npackets_reply = flow_info[match.nw_proto][match.nw_dst][match.tp_dst][match.nw_src][match.tp_src]['packet_count']
            except KeyError:
                npackets_reply = 0
            reply_rate = float(npackets_reply) / (flow.packet_count) if float(npackets_reply) / (flow.packet_count) < 1 else 1.00

            ssrc_sproto_sdst_stpdst_nflows = 0
            for tpsrc in flow_info[match.nw_proto][match.nw_src]:
                if match.nw_dst in flow_info[match.nw_proto][match.nw_src][tpsrc]:
                    if match.tp_dst in flow_info[match.nw_proto][match.nw_src][tpsrc][match.nw_dst]:
                        ssrc_sproto_sdst_stpdst_nflows += 1
                        
            # flow_stats_record = {"protocol" : protocol, "transfer_rate" : transfer_rate, "packet size" : average_packet_size, "ssrc_sproto_percentage_hosts" : ssrc_sproto_percentage_hosts,
            #     "ssrc_sproto_sdst_nflows" : ssrc_sproto_sdst_nflows,"ssrc_sproto_sdst_stpdst_nflows":ssrc_sproto_sdst_stpdst_nflows, "reply rate" : reply_rate}
            # log.info(flow_stats_record)

            decider = randint(1,300)    # to choose whether to save the data sample or not (in some case, 1 type of attack could generate a lot of 
                                        # same-type flows, which might produce a lot of identical data samples in 1 interval)
            
            # Label and save sample into file
            if match.nw_src == IPAddr('10.0.0.1') and transfer_rate != 0 and dicider % 123 == 0:
                file.write(("{},{:.2f},{},{:.2f},{},{},{},{:.2f},tcpsynflood\n").format(protocol, transfer_rate, average_packet_size, 
                ssrc_sproto_percentage_hosts, len(ssrc_sproto_nhosts), ssrc_sproto_sdst_nflows, ssrc_sproto_sdst_stpdst_nflows, reply_rate))
                
        Timer(self.interval, self.flow_stats_request)

    # Handle switch connection
    def _handle_ConnectionUp (self, event):
        self.connection = event.connection
        time.sleep(1)
        self.flow_stats_request()
    
    # Send FlowStatisticsRequest messsage
    def flow_stats_request(self):
        self.connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

def launch():
    log.info('Collecting data from flow')
    core.registerNew(collect_stats)



