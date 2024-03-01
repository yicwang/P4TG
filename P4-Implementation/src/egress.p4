/* Copyright 2022-present University of Tuebingen, Chair of Communication Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Steffen Lindner (steffen.lindner@uni-tuebingen.de)
 */
 
#include "./libs/egress/Header_Replace.p4"
control egress(
    inout header_t hdr,
    inout egress_metadata_t eg_md, in egress_intrinsic_metadata_t eg_intr_md, in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    Header_Replace() header_replace;
    bit<16> pkt_len = 0;
    bit<32> index = 0;

    Add_64_64(4096) rate_l1;
    Add_64_64(4096) rate_l2;
    Add_64_64(4096) app;

    bit<64> dummy = 0;

    Register<bit<32>, PortId_t>(256, 0) tx_seq;

    RegisterAction<bit<32>, PortId_t, bit<32>>(tx_seq) get_next_tx_seq = {
            void apply(inout bit<32> value, out bit<32> read_value) {
                read_value = value;
                value = value + 1;
            }
    };

    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) frame_counter;

    action nop() {
        frame_counter.count();
    }

    table frame_size_monitor {
        key = {
            pkt_len: range;
            eg_intr_md.egress_port: exact;
        }
        actions = {
            nop;
        }
        size = 512;
        counters = frame_counter;
    }

    action set_tx() {
        hdr.path.tx_tstmp = eg_intr_from_prsr.global_tstamp;
    }

    table is_egress {
        key = {
            eg_intr_md.egress_port: exact;
        }
        actions = {
            set_tx;
        }
        size = 32;
    }

    action no_action() {}
    table is_tx_recirc {
        key = {
            eg_intr_md.egress_port: exact;
        }
        actions = {
            no_action;
        }
        size = 32;
    }

    action init_monitor_header(bit<15> index) {
        hdr.monitor.index = index;
    }

    table monitor_init {
        key = {
            eg_intr_md.egress_port: exact;
            hdr.monitor.index: exact;
        }
        actions = {
            init_monitor_header;
        }
        size = 32;
    }

    action monitor_stream_rate(bit<32> idx) {
        index = idx;
    }

    table monitor_stream {
        key = {
            eg_intr_md.egress_port: exact;
            hdr.path.app_id: exact;
            hdr.path.dst_port: exact;
        }
        actions = {
            monitor_stream_rate;
        }
        size = 256;
    }

    action checksum_preprocess() {
        eg_md.checksum_md.inner_ipv4_src_addr_ones_complement = ~hdr.ipv4.src_addr;
        eg_md.checksum_md.inner_ipv4_dst_addr_ones_complement = ~hdr.ipv4.dst_addr;
        eg_md.checksum_md.checksum_all_ones_8b = ~(8w0);
        eg_md.checksum_md.inner_ipv4_protocol_ones_complement = ~(IP_PROTOCOL_UDP);
        eg_md.checksum_md.inner_ipv4_payload_length_ones_complement = ~eg_md.checksum_md.inner_ipv4_payload_length;
    }

    action action_encap_pkt_udp_v4() {
        hdr.outer_ethernet.setValid();
        hdr.outer_ethernet.ether_type = ETHERTYPE_IPV4;
        hdr.outer_ethernet.src_addr = hdr.ethernet.src_addr;
        hdr.outer_ethernet.dst_addr = hdr.ethernet.dst_addr;

        hdr.outer_ipv4.setValid();
        hdr.outer_ipv4.version = 4w4;
        hdr.outer_ipv4.ihl = 4w5;
        hdr.outer_ipv4.total_len = hdr.ipv4.total_len + 16w50;
        hdr.outer_ipv4.identification = 1234; // Can change;
        hdr.outer_ipv4.flags = 3w0;
        hdr.outer_ipv4.frag_offset = 13w0;
        hdr.outer_ipv4.ttl = 64;
        hdr.outer_ipv4.protocol = IP_PROTOCOL_UDP;
        hdr.outer_ipv4.hdr_checksum = 16w0;
        hdr.outer_ipv4.src_addr = 32w0; // will be changed later
        hdr.outer_ipv4.dst_addr = 32w0; // will be changed later. 10.249.243.224

        hdr.outer_udp.setValid();
        hdr.outer_udp.dst_port = UDP_PORT_VXLAN;
        hdr.outer_udp.src_port = 1234; // Can change
        hdr.outer_udp.len = hdr.ipv4.total_len + 16w30;
        hdr.outer_udp.checksum = 16w0;

        hdr.vxlan.setValid();
        hdr.vxlan.vni = (bit<24>)eg_intr_md.egress_port;
        hdr.vxlan.flags = 0x8;
        hdr.vxlan.reserved2 = 8w0;

        //hdr.ethernet.src_addr = BVS_MAGIC_SRC_MAC;
        //hdr.ethernet.dst_addr = BVS_MAGIC_DST_MAC;
        
        eg_md.checksum_md.inner_ipv4_payload_length = hdr.ipv4.total_len - (bit<16>)sizeInBytes(hdr.ipv4);
    }

    action action_modify_outer_ipv4(ipv4_addr_t src_ip, ipv4_addr_t dst_ip) {
        hdr.outer_ipv4.src_addr = src_ip;
        hdr.outer_ipv4.dst_addr = dst_ip;
    }

    table outer_ipv4_table {
        key = {
            eg_intr_md.egress_port: exact;
        }
        actions = {
            action_modify_outer_ipv4;
        }
        const entries = {
            (256) : action_modify_outer_ipv4(32w0x64428e6e, 32w0x64428e6c); // 100.66.142.110 -> 100.66.142.108
            (260) : action_modify_outer_ipv4(32w0x64428f6e, 32w0x64428f6c); // 100.66.143.110 -> 100.66.143.108
            (264) : action_modify_outer_ipv4(32w0x6442906e, 32w0x6442906c); // 100.66.144.110 -> 100.66.144.108
            (268) : action_modify_outer_ipv4(32w0x6442916e, 32w0x6442916c); // 100.66.145.110 -> 100.66.145.108
            (272) : action_modify_outer_ipv4(32w0x6442926e, 32w0x6442926c); // 100.66.146.110 -> 100.66.146.108
            (276) : action_modify_outer_ipv4(32w0x6442936e, 32w0x6442936c); // 100.66.147.110 -> 100.66.147.108
            (280) : action_modify_outer_ipv4(32w0x6442946e, 32w0x6442946c); // 100.66.148.110 -> 100.66.148.108
            (284) : action_modify_outer_ipv4(32w0x6442956e, 32w0x6442956c); // 100.66.149.110 -> 100.66.149.108
            (440) : action_modify_outer_ipv4(32w0x64428e6e, 32w0x64428e6c); // 100.66.142.110 -> 100.66.142.108
            (444) : action_modify_outer_ipv4(32w0x64428f6e, 32w0x64428f6c); // 100.66.143.110 -> 100.66.143.108
        }
        size = 16;
    }

    apply {
        bit<64> app_count = 0;

        if(hdr.monitor.isValid()) {
            monitor_init.apply();
            hdr.monitor.tstmp = eg_intr_from_prsr.global_tstamp;
            hdr.monitor.port = eg_intr_md.egress_port;
            rate_l1.apply(hdr.monitor.byte_counter_l1, 0, (bit<32>)eg_intr_md.egress_port); // do not count monitor packet size
            rate_l2.apply(hdr.monitor.byte_counter_l2, 0, (bit<32>)eg_intr_md.egress_port); //
            app.apply(app_count, 0, (bit<32>)hdr.monitor.index);

            hdr.monitor.app_counter = (bit<48>) app_count;
        }
        else {
            monitor_stream.apply();

            bit<64> l_1 = 0;
            bit<64> l_2 = 0;

            if(!is_tx_recirc.apply().hit) {
                l_1 = (bit<64>)(eg_intr_md.pkt_length + 20);
                l_2 = (bit<64>)(eg_intr_md.pkt_length);

                pkt_len = eg_intr_md.pkt_length;
            }
            else { // we need to remove pkt gen header size
                l_1 = (bit<64>)(eg_intr_md.pkt_length + 20 - 6);
                l_2 = (bit<64>)(eg_intr_md.pkt_length - 6);


                pkt_len = eg_intr_md.pkt_length - 6; // minus pkt gen header

                // we are on tx recirc; set sequence number
                if(hdr.ipv4.isValid() && hdr.ipv4.protocol == IP_PROTOCOL_UDP && hdr.path.dst_port == 50083) { // make sure its PTG's traffic
                  hdr.path.seq = get_next_tx_seq.execute(eg_intr_md.egress_port);
                }
            }

            rate_l1.apply(dummy, l_1, (bit<32>)eg_intr_md.egress_port);
            rate_l2.apply(dummy, l_2, (bit<32>)eg_intr_md.egress_port);

            app.apply(dummy, l_2, index);

            // set tx tstamp
            if(hdr.ipv4.isValid() && hdr.ipv4.protocol == IP_PROTOCOL_UDP && hdr.path.dst_port == 50083) { // make sure its PTG's traffic
                is_egress.apply();
            }

            header_replace.apply(hdr, eg_intr_md);

            frame_size_monitor.apply();

            action_encap_pkt_udp_v4();
            outer_ipv4_table.apply();
            checksum_preprocess();
        }


    }
}
