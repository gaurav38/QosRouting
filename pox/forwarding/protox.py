# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Start and run proto-x on OpenFlow Switches.

"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
import pox.lib.packet as pkt
from pox.lib.recoco import Timer
import time
from pox.openflow.libopenflow_01 import *

log = core.getLogger()
dpids = []
ports = {}
LAT_TYPE    = 0x07c3
dpid_ts = {}
dpid_latency = {}

def _handle_ConnectionUp (event):
  """
  Tell all switches to forwards latency packets to controller
  """
  print "Connected to switch",dpidToStr(event.dpid)
  SwHandler(event)
  connection = event.connection
  match = of.ofp_match(dl_type = LAT_TYPE,dl_dst = pkt.ETHERNET.NDP_MULTICAST)
  msg = of.ofp_flow_mod()
  msg.priority = 65000
  msg.match = match
  msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
  connection.send(msg)

class SwHandler(object):
  
  connection = None
  dpid = None
  def __init__(self,event):
    self.connection = event.connection
    self.dpid = event.connection.dpid
    dpids.append(self.dpid)
    ports[dpidToStr(event.dpid)] = {}
    print "Add ports to link status DB"
    dpid_ts[self.dpid] = 0.000
    dpid_latency[self.dpid] = 0.000
    for p in event.ofp.ports:
      port = [str(p.hw_addr), 0.0, 100, 0, 0]
      ports[dpidToStr(event.dpid)][p.port_no] = port

    core.openflow.addListenerByName("PacketIn", self.handle_pkt) 
    core.openflow.addListenerByName("SwitchDescReceived", self.handle_switch_desc) 

  def handle_pkt (self, event):
    """
    Handle incoming latency packets
    """
    packet = event.parsed
#    print packet
#    print packet.effective_ethertype

    if packet.effective_ethertype == LAT_TYPE:
      port = packet.src
      [prevtime, mac, swdpdest, swdpsrc] = packet.payload.split(',')
      prevtime = float(prevtime)
      currtime = time.time()
      dest_dpid = dpidToStr(event.dpid)
      src_dpid = dpidToStr(self.dpid)
      #print src_dpid,"-------",dest_dpid
      #print swdpsrc,"-------",swdpdest
      if src_dpid == swdpsrc and dest_dpid == swdpdest:
        #print "DPID matched"
        latency = round(((currtime - prevtime)*1000), 4) - dpid_latency[self.dpid] - dpid_latency[event.dpid]
        #swd = ports[dpidToStr(self.dpid)]
        swd = ports[swdpsrc]
        for k in swd:
          if swd[k][0] == mac:
            break
        ports[swdpsrc][k][1] = latency
        print swdpsrc,"->",mac,"--",latency

  def handle_switch_desc(self, event):
    currtime = time.time()
    prevtime = dpid_ts[event.dpid]
    latency = round(((currtime - prevtime)*1000), 4)
    dpid_latency[event.dpid] = latency/2

def find_latency(dpid):
  for key in ports[dpidToStr(dpid)]:
    if(key != 65534):
      packet = of.ofp_packet_out(action = of.ofp_action_output(port = key))
      packet.data = create_lat_pkt(dpid,key,ports[dpidToStr(dpid)][key][0])
      #print "Sending to ",dpid," key ", key
      core.openflow.sendToDPID(dpid, packet)

def create_lat_pkt(dpid, port, port_mac):
  pkt1 = pkt.ethernet(type=LAT_TYPE)
  pkt1.src = port_mac
  for l in core.openflow_discovery.adjacency:
      if ((l.dpid1 == dpid) and (l.port1 == port)):
        #print "Sending for",l
        pkt1.dst = pkt.ETHERNET.NDP_MULTICAST #need to decide
        pkt1.payload = str(time.time()) + ',' + port_mac + ',' + dpidToStr(l.dpid2) + ',' + dpidToStr(l.dpid1)
        return pkt1.pack()

def find_latency_to_dpid(dpid):
  pkt = ofp_stats_request(type=OFPST_DESC)
  dpid_ts[dpid] = time.time()
  core.openflow.sendToDPID(dpid, pkt)  

def find_latency1():
  #print dpid_latency
  for dpid in dpids:
    find_latency_to_dpid(dpid)
  #print ports
  for dpid in dpids:
    find_latency(dpid)
  #find_latency(dpids[0])
#    print ports[dpidToStr(dpid)]

Timer(10, find_latency1, recurring = True)

def launch ():
  from pox.openflow.discovery import launch
  launch()
  def start_launch ():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
#    core.openflow_discovery.addListenerByName("LinkEvent", _handle_LinkEvent)
    print "Latency monitor"
    log.debug("Latency monitor running")
  core.call_when_ready(start_launch, "openflow_discovery") 
#  core.openflow.addListenerByName("PortStatus", _handle_PortStatus)
#  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
#  log.info("Latency monitor running.")

#print "========================================================BLAH!!!============================================================"
