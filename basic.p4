/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 0x06;
const bit<8> TYPE_UDP = 0x11;
const bit<8> TYPE_OSPF = 0x59;
const bit<8> TYPE_ICMP = 0x01;

/*** TCP Flags ***/
const bit<9> FLAG_NS = 0x100;
const bit<9> FLAG_CWR = 0x080;
const bit<9> FLAG_ECE = 0x040;
const bit<9> FLAG_URG = 0x020;
const bit<9> FLAG_ACK = 0x010;
const bit<9> FLAG_PSH = 0x008;
const bit<9> FLAG_RST = 0x004;
const bit<9> FLAG_SYN = 0x002;
const bit<9> FLAG_FIN = 0x001;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNum;
    bit<32> ackNum;
    bit<4>  headerSize;
    bit<3>  reserve;
    bit<9>  flags;
    bit<16> windowSize;
    bit<16> chksum;
    bit<16> urg;
    bit<32> options;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> totalLen;
    bit<16> chksum;
}

header ospf_t {
    bit<8>   version;
    bit<8>  ospfType;
    bit<16>  packLen;
    bit<32> routerID;
    bit<32>   areaID;
    bit<16>   chksum;
    bit<16> authType;
    bit<32>  authOne;
    bit<32>  authTwo;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> icmp_checksum;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
    ospf_t       ospf;
    icmp_t       icmp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            TYPE_OSPF: parse_ospf;
            TYPE_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_ospf {
        packet.extract(hdr.ospf);
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action forward (egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }
    action drop () {
        mark_to_drop(standard_metadata);
    }
    table forwarding {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }
    table filter_src {
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            NoAction;
            drop;
        }
        size = 1024;
        default_action = NoAction();
    }
    table filter_ipv4_protocol {
        key = {
            hdr.ipv4.protocol: exact;
        }
        actions = {
            NoAction;
            drop;
        }
        size = 1024;
        default_action = NoAction();
    }
    table filter_tcp_flags {
        key = {
            hdr.tcp.flags: exact;
        }
        actions = {
            NoAction;
            drop;
        }
        size = 1024;
        default_action = NoAction();
    }
    apply {
        if(hdr.ipv4.isValid()){
            forwarding.apply();
            filter_src.apply();
            filter_protocol.apply();
            filter_flags.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.ospf);
        packet.emit(hdr.icmp);
    }
}

/*************************************************************************
**************************  S W I T C H   ********************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
