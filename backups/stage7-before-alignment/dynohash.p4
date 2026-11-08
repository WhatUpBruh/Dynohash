
#include <core.p4>
#include <v1model.p4>

// ----------------------------------------------------
// DynoHash - Stage 7B
// IPv4 five-tuple hashing and 64-bucket forwarding
// Target: BMv2 simple_switch_grpc (v1model)
// ----------------------------------------------------

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;

// ----------------------------------------------------
// Header definitions
// ----------------------------------------------------

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

struct metadata {
    bit<6> bucket_id;
}

// ----------------------------------------------------
// Parser
// ----------------------------------------------------

parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    state start {
        packet.extract(hdr.ethernet);

        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);

        // Only parse transport ports when:
        // - More Fragments flag is zero
        // - Fragment offset is zero
        // - Protocol is TCP or UDP
        //
        // The DF flag may be either zero or one.
        transition select(
            hdr.ipv4.flags & 3w1,
            hdr.ipv4.fragOffset,
            hdr.ipv4.protocol
        ) {
            (3w0, 13w0, PROTO_TCP): parse_tcp;
            (3w0, 13w0, PROTO_UDP): parse_udp;
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
}

// ----------------------------------------------------
// Verify checksum
// ----------------------------------------------------

control MyVerifyChecksum(
    inout headers hdr,
    inout metadata meta
) {
    apply { }
}

// ----------------------------------------------------
// Ingress pipeline
// ----------------------------------------------------

control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {

    action forward_to_detector(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    table bucket_to_detector {
        key = {
            meta.bucket_id: exact;
        }

        actions = {
            forward_to_detector;
            drop;
        }

        size = 64;
        default_action = drop();
    }

    apply {
        // A 32-bit temporary is needed because the hash()
        // range argument must be able to represent 64.
        bit<32> hash_bucket;

        if (
            hdr.ipv4.isValid() &&
            hdr.ipv4.version == 4 &&
            hdr.ipv4.ihl == 5 &&
            (hdr.tcp.isValid() || hdr.udp.isValid())
        ) {

            if (hdr.tcp.isValid()) {

                hash(
                    hash_bucket,
                    HashAlgorithm.crc32,
                    (bit<32>) 0,
                    {
                        hdr.ipv4.srcAddr,
                        hdr.ipv4.dstAddr,
                        hdr.ipv4.protocol,
                        hdr.tcp.srcPort,
                        hdr.tcp.dstPort
                    },
                    (bit<32>) 64
                );

            } else {

                hash(
                    hash_bucket,
                    HashAlgorithm.crc32,
                    (bit<32>) 0,
                    {
                        hdr.ipv4.srcAddr,
                        hdr.ipv4.dstAddr,
                        hdr.ipv4.protocol,
                        hdr.udp.srcPort,
                        hdr.udp.dstPort
                    },
                    (bit<32>) 64
                );

            }

            // hash_bucket is in the range 0 to 63.
            // Six bits are sufficient for the bucket ID.
            meta.bucket_id = (bit<6>) hash_bucket;

            // P4Runtime will populate this table.
            bucket_to_detector.apply();

        } else {

            // Drop unsupported or invalid traffic.
            drop();

        }
    }
}

// ----------------------------------------------------
// Egress pipeline
// ----------------------------------------------------

control MyEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    apply { }
}

// ----------------------------------------------------
// Compute checksum
// ----------------------------------------------------

control MyComputeChecksum(
    inout headers hdr,
    inout metadata meta
) {
    apply { }
}

// ----------------------------------------------------
// Deparser
// ----------------------------------------------------

control MyDeparser(
    packet_out packet,
    in headers hdr
) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

// ----------------------------------------------------
// BMv2 v1model architecture
// ----------------------------------------------------

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
