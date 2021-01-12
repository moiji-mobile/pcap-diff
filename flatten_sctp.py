#!/usr/bin/python

"""
(C) Copyright 2016-2017 Holger Hans Peter Freyther

GNU AGPLv3+
"""

from scapy.all import rdpcap, Ether, IP, SCTP, SCTPChunkData, wrpcap
import sys

inp_fn = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"
out_fn = sys.argv[2] if len(sys.argv) > 2 else "output.pcap"

pcap = rdpcap(inp_fn)
pkts = []

i = 0
seq = 0
for pkt in pcap:
    ip = pkt['IP']
    layer = ip.payload
    sctp = ip.payload
    while layer.name != 'NoPayload':
        if layer.name == 'SCTP':
            sport = layer.sport
            dport = layer.dport
            tag = layer.tag
        if layer.name == 'SCTPChunkData':
            # re-create the chunkdata as I don't find the routine to just have this data...
            newpkt=Ether()/ip/sctp/SCTPChunkData(reserved=0, delay_sack=0, unordered=0, beginning=1, ending=1, stream_id=layer.stream_id, proto_id=layer.proto_id, stream_seq=layer.stream_seq, tsn=layer.tsn, data=layer.data)
            newpkt.time=pkt.time
            pkts.append(newpkt)
            seq = seq + 1
        layer = layer.payload
    i = i + 1

wrpcap(out_fn, pkts)
