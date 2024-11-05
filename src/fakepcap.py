#!/usr/bin/env python3
import math
import hashlib
import random
import struct
import socket

import dpkt
from dpkt.tcp import TH_SYN, TH_ACK, TH_PUSH, TH_FIN, TCP_WIN_MAX

#
# Tool to take raw request/response data and build enough of a pcap to run thru Suricata
#

# max ethernet packet size minus headers
MAX_PACKET_SIZE = 1500 - (20 * 2 - 14)

DIR_OUT = 1     # src -> dst
DIR_IN = 2      # dst -> src

# time between packets
PACKET_DELAY = 0.01

class TCPConnection(object):
    def __init__(self, timestamp: int, srcip: str, srcport: int, dstip: str, dstport: int):
        self.srcip = socket.inet_aton(srcip)
        self.srcport = srcport
        self.src_seq = self.random_seq()
        self.src_mac = self.get_mac(self.srcip)

        self.dstip = socket.inet_aton(dstip)
        self.dstport = dstport
        self.dst_seq = self.random_seq()
        self.dst_mac = self.get_mac(self.dstip)

        self.last_direction = DIR_OUT

        # Delay the timestamp so the first packet with payload matches the original connection
        self.timestamp = timestamp - 3 * PACKET_DELAY if timestamp else 1564617600.0
        self.packets = []

        self.three_way_handshake()

    def add(self, direction: int, payload: bytes):
        if len(payload) > MAX_PACKET_SIZE:
            [ self.add(direction, payload[i:i+MAX_PACKET_SIZE]) for i in range(0, len(payload), MAX_PACKET_SIZE) ]
        else:
            self.build_tcp_packet(direction, data=payload)
            # ACK the data, otherwise Suricata will complain if one end goes out-of-window
            ack_direction = DIR_IN if direction == DIR_OUT else DIR_OUT
            self.build_tcp_packet(direction=ack_direction)

    def checksum(self, data):
        if len(data) % 2:
            data += b'\x00'

        s = sum(struct.unpack('!%sH' % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        #return socket.htons(~s & 0xffff)
        return ~s & 0xffff

    def three_way_handshake(self):
        self.build_tcp_packet(direction=DIR_OUT, tcp_flags=TH_SYN)
        self.build_tcp_packet(direction=DIR_IN, tcp_flags=TH_SYN|TH_ACK)
        self.build_tcp_packet(direction=DIR_OUT, tcp_flags=TH_ACK)

    def last_ack(self):
        direction = DIR_OUT if self.last_direction == DIR_IN else DIR_IN
        self.build_tcp_packet(direction=DIR_OUT, tcp_flags=TH_ACK)

    def teardown(self):
        self.build_tcp_packet(direction=DIR_OUT, tcp_flags=TH_ACK|TH_FIN)
        self.build_tcp_packet(direction=DIR_IN, tcp_flags=TH_ACK|TH_FIN)
        self.build_tcp_packet(direction=DIR_OUT, tcp_flags=TH_ACK)

    def build_tcp_packet(self, direction, tcp_flags=None, data=b""):
        self.last_direction = direction

        #
        # Set various packet options based on TCP flags and the presence of data
        #

        if tcp_flags == TH_SYN:
            # 3WHS
            seq = self.src_seq
            ack = 0
            self.incr_seq(direction, 1)
        elif tcp_flags == TH_SYN|TH_ACK:
            seq = self.dst_seq
            ack = self.src_seq
            self.incr_seq(direction, 1)
        elif tcp_flags == TH_ACK and not data:
            # the lack ACK of the 3WHS and teardown comes from the client side
            seq = self.src_seq
            ack = self.dst_seq
        elif tcp_flags == TH_ACK|TH_FIN:
            # teardown
            seq = self.src_seq if direction == DIR_OUT else self.dst_seq
            ack = self.dst_seq if direction == DIR_OUT else self.src_seq
            self.incr_seq(direction, 1)
        elif len(data) > 0:
            if not tcp_flags:
                tcp_flags = TH_ACK | TH_PUSH

            seq = self.src_seq if direction == DIR_OUT else self.dst_seq
            ack = self.dst_seq if direction == DIR_OUT else self.src_seq
            self.incr_seq(direction, len(data))
        else:
            seq = self.src_seq if direction == DIR_OUT else self.dst_seq
            ack = self.dst_seq if direction == DIR_OUT else self.src_seq

        if not tcp_flags:
            tcp_flags = TH_ACK

        tcp = dpkt.tcp.TCP(
            flags = tcp_flags,
            sport = self.srcport if direction == DIR_OUT else self.dstport,
            dport = self.dstport if direction == DIR_OUT else self.srcport,
            seq = seq,
            ack = ack,
            win = TCP_WIN_MAX,
            sum = 0,
            data = data
        )
        tcp_packet = tcp.pack()
        ip = dpkt.ip.IP(
            len = 20 + len(tcp_packet),
            id = 0,
            ttl = 64,
            sum = 0,
            src = self.srcip if direction == DIR_OUT else self.dstip,
            dst = self.dstip if direction == DIR_OUT else self.srcip,
            p = dpkt.ip.IP_PROTO_TCP,
            data = tcp_packet
        )
        # Create the pseudo-header
        pheader = struct.pack('!4s4sHH', ip.src, ip.dst, ip.p, len(tcp))
        tcp.sum = 0
        tcp.sum = self.checksum(pheader + bytes(tcp))

        ip.data = tcp
        ip_packet = ip.pack()
        ethernet_packet = dpkt.ethernet.Ethernet(
            src = self.src_mac if direction == DIR_OUT else self.dst_mac,
            dst = self.dst_mac if direction == DIR_OUT else self.src_mac,
            type = dpkt.ethernet.ETH_TYPE_IP,
            data = ip_packet
        ).pack()
        self.packets.append(ethernet_packet)

    def get_timestamp(self):
        return self.timestamp

    def get_packets(self):
        return self.packets

    def incr_seq(self, direction: int, step: int):
        if direction == DIR_OUT:
            self.src_seq += step
            self.src_seq = self.src_seq & 0xffffffff
        elif direction == DIR_IN:
            self.dst_seq += step
            self.dst_seq = self.dst_seq & 0xffffffff

    @staticmethod
    def random_seq():
        x = random.randint(0, 0xffffffff)
        return x & 0xffffffff

    @staticmethod
    def get_mac(data):
        # Generating completely random mac address OUIs can get weird when you hit a reserved prefix.
        # Use some hardcoded prefixes for defunct companies for funsies.
        common_mac_prefixes = [
            "\x00\x06\x8C", # 3com
            "\x00\x07\x5C", # eastman kodak
            "\x00\x00\xD8", # novell
            "\x00\x0D\x72", # 2wire
            "\x00\x60\xBB", # cabletron
            "\x00\x60\x7D", # sentient
            "\x00\xE0\x7B", # bay
            "\x00\x08\x1D", # ipsilon
            "\x00\x80\xD3", # shiva
            "\x00\x1C\x7F", # checkpoint (lol)
        ]
        sha = hashlib.sha256()
        sha.update(data)
        mac = random.choice(common_mac_prefixes) + sha.hexdigest()[0:3]
        return mac.encode()

class FakePcap(object):
    def __init__(self, filename):
        self.connections = dict()
        self.filename = filename
        self.saw_traffic = False

    def add(self, srcip, srcport, dstip, dstport, payload: bytes, timestamp=None):
        if len(payload) == 0:
            return
        self.saw_traffic = True

        five_tuple = (timestamp, srcip, srcport, dstip, dstport)
        five_tuple_reversed = (timestamp, dstip, dstport, srcip, srcport)

        if five_tuple not in self.connections and five_tuple_reversed not in self.connections:
            self.connections[five_tuple] = TCPConnection(*five_tuple)

        if five_tuple in self.connections:
            self.connections[five_tuple].add(DIR_OUT, payload)
        elif five_tuple_reversed in self.connections:
            self.connections[five_tuple_reversed].add(DIR_IN, payload)

    def save(self):
        # We didn't see anything, don't write a file
        if not self.saw_traffic:
            return

        f = open(self.filename, "wb")
        f.write(self.pcap_header())

        for _, connection in sorted(self.connections.items(), key=lambda x: x[1].get_timestamp()):
            connection.last_ack()
            connection.teardown()

            timestamp = connection.get_timestamp()
            for packet in connection.get_packets():
                fractions, time_sec = math.modf(timestamp)
                time_micro = fractions * 1000000
                f.write(self.pcap_record(int(time_sec), int(time_micro), len(packet)))
                f.write(packet)

                # small but measurable delay between packets
                timestamp += PACKET_DELAY

        f.close()

    # ref: https://wiki.wireshark.org/Development/LibpcapFileFormat
    # file header at the beginning of every pcap
    @staticmethod
    def pcap_header():
        return struct.pack("IHHIIII",
            0xa1b2c3d4, # magic
            2,          # major ver
            4,          # minor ver
            0,          # GMT offset
            0,          # sigfigs
            65535,      # snaplen
            1           # data link type
        )

    # record header at beginning of each packet
    @staticmethod
    def pcap_record(time_sec, time_micro, pkt_len):
        return struct.pack("IIII",
            time_sec,   # timestamp seconds
            time_micro, # timestamp microseconds
            pkt_len,    # num octects saved
            pkt_len     # actual num octect
        )

def main():
    fp = FakePcap("out.pcap")
    fakedata = "X"*2046
    fp.add("1.1.1.1", 23423, "2.2.2.2", 80, fakedata.encode(), timestamp=1564617600.0)
    fp.add("2.2.2.2", 80, "1.1.1.1", 23423, "200 HTTP\nHere's some data!".encode(), timestamp=1564617600.0)
    fp.add("3.3.3.3", 9000, "4.4.4.4", 80, fakedata.encode(), timestamp=1564617800.0)
    fp.add("4.4.4.4", 80, "3.3.3.3", 9000, "200 HTTP\nHere's some other data!".encode(), timestamp=1564617800.0)
    fp.save()

if __name__ == "__main__": # pragma: no cover
    main()
