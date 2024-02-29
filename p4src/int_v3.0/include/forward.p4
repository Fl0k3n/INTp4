/*
 * Copyright 2020-2021 PSNC, FBK
 *
 * Author: Damian Parniewicz, Damu Ding
 *
 * Created in the GN4-3 project.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#ifdef BMV2
control Forward(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
#elif TOFINO
control Forward(inout headers hdr, inout metadata meta, inout ingress_intrinsic_metadata_for_tm_t standard_metadata) {
#endif

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(bit<48> srcAddr, bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action reply_arp(bit<48> targetMac) {
        bit<32> tmp;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = targetMac;
        hdr.arp.opcode = 2;
        hdr.arp.dstMac = hdr.arp.srcMac;
        hdr.arp.srcMac = targetMac;
        tmp = hdr.arp.srcIp;
        hdr.arp.srcIp = hdr.arp.dstIp;
        hdr.arp.dstIp = tmp;
    }

    table arp_exact {
      key = {
        hdr.arp.dstIp: exact;
      }
      actions = {
          reply_arp;
          drop;
          NoAction;
      }
      size = 1024;
      default_action = drop();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.arp.isValid()) {
          if (hdr.arp.opcode == 1) {
            arp_exact.apply();
          }
          else if (hdr.arp.opcode == 2) {
            // switch_packet();
            drop();
          }
        } else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}
