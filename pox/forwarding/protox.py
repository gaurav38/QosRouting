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

log = core.getLogger()
dpids = []
ports = {}
LAT_TYPE    = 0x07c3

def _handle_ConnectionUp (event):
  """
  Tell all switches to forwards latency packets to controller
  """
  print "Connected to switch",dpidToStr(event.dpid)
  SwHandler(event)
  connection = event.connection
  match = of.ofp_match(dl_type = LAT_TYPE)
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
    for p in event.ofp.ports:
      port = [str(p.hw_addr), 0.0, 100, 0, 0]
      ports[dpidToStr(event.dpid)][p.port_no] = port

    core.openflow.addListenerByName("PacketIn", self.handle_pkt)  

  def handle_pkt (self, event):
    """
    Handle incoming latency packets
    """
    packet = event.parsed
#    print packet
#    print packet.effective_ethertype

    if packet.effective_ethertype == self.LAT_TYPE:
      port = packet.src
      [prevtime, mac, swdp] = packet.payload.split(',')
      prevtime = float(prevtime)
      currtime = time.time()
      src_dpid = event.dpid
      print dpidToStr(src_dpid),"-------",swdp
      if event.dpid == int(swdp):
        latency = currtime - prevtime
        swd = ports[dpidToStr(self.dpid)]
        for k in swd:
          if swd[k][0] == mac:
            break
        ports[dpidToStr(self.dpid)][k][1] = latency
        print mac,latency

def find_latency(dpid):
  for key in ports[dpidToStr(dpid)]:
    packet = of.ofp_packet_out(action = of.ofp_action_output(port = key))
    packet.data = create_lat_pkt(dpid,key,ports[dpidToStr(dpid)][key][0])
    core.openflow.sendToDPID(dpid, packet)

def create_lat_pkt(dpid, port, port_mac):
  pkt1 = pkt.ethernet(type=LAT_TYPE)
  pkt1.src = port_mac
  for l in core.openflow_discovery.adjacency:
      if ((l.dpid1 == dpid) and (l.port1 == port)):
        print "Sending for",l
        pkt1.dst = pkt.ETHERNET.NDP_MULTICAST #need to decide
        pkt1.payload = str(time.time()) + ',' + port_mac + ',' + str(l.dpid2)
        return pkt1.pack()

def find_latency1():
  print ports
  for dpid in dpids:
    find_latency(dpid)
#    print ports[dpidToStr(dpid)]

Timer(20, find_latency1, recurring = True)

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
