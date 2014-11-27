from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr, strToDPID
import pox.lib.packet as pkt
from pox.lib.recoco import Timer
from pox.openflow.libopenflow_01 import *
import protox
#import pox.forwarding.protox as dpids
from collections import defaultdict

# link_costs: [sw1][sw2] = cost
link_costs = defaultdict(lambda:defaultdict(lambda:None))
switch_adjacency = defaultdict(lambda:defaultdict(lambda:None))
cf_constants = {}
tos_constants = []

# create lists for different kinds of tos values
voice_tos = [46, 40, 32, 38, 36]
video_tos = [30, 28]
business_tos = [20, 22, 12, 14]

def get_cf_consts():
  voice = [100, 0.1, 0.003]
  video = [100, 0.07, 0.007]
  business = [100, 0.01, 0.01]
  besteffort = [100, 0, 0]
  cf_constants['voice'] = voice
  cf_constants['video'] = video
  cf_constants['business'] = business
  cf_constants['besteffort'] = besteffort

def get_tos_constants(tos):
  if tos in voice_tos:
    tos_constants = cf_constants['voice']
  elif tos in video_tos:
    tos_constants = cf_constants['video']
  elif tos in business_tos:
    tos_constants = cf_constants['business']
  else:
    tos_constants = cf_constants['besteffort']   


def create_adjacency():
  for l in core.openflow_discovery.adjacency:
    switch_adjacency[l.dpid1][l.port1] = l.dpid2

def find_cost(tos):
  create_adjacency()
  get_cf_consts()
  get_tos_constants(tos)

  switch_dict = {}
  # Iterate through all the switches and find the cost to its neighboring switch. Ignore port 65534
  for switch in protox.dpids:
    switchStr = dpidToStr(switch)
    # Get this switch latency map
    switch_dict = protox.ports[switchStr]
    # Iterate through all the ports of this switch. Ignore port 65534
    port_list = []
    for port in switch_dict:
      port_list = switch_dict[port]
      dest_switch = switch_adjacency[switch][port]
      
      # Get the values of BW, latency, Rx and Tx
      latency = port_list[1]
      bw = port_list[2]
      rx = port_list[3]
      tx = port_list[4]

      # Just a "bad" implementation of cost function based on rough assumption
      n = 0
      if tos_constants[1] is not 0:
        n = 1
      cost = tos_constants[0]*bw + n*(tos_constants[1]*latency + tos_constants[2]*tx)
  
      # Store the calculated cost value in the dictionary
      link_costs[switch][dest_switch] = cost
      print "blah" 
  return link_costs
    
