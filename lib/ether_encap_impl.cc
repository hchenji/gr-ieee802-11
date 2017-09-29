/*
 * Copyright (C) 2013 Bastian Bloessl <bloessl@ccs-labs.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "ether_encap_impl.h"
#include "utils.h"

#include <gnuradio/io_signature.h>
#include <gnuradio/block_detail.h>
#include <string>

using namespace gr::ieee802_11;

ether_encap_impl::ether_encap_impl(bool debug, std::vector<uint8_t> src_mac) :
        block("ether_encap",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
        d_debug(debug),
        d_last_seq(123) {

    message_port_register_out(pmt::mp("to tap"));
    message_port_register_out(pmt::mp("to wifi"));

    message_port_register_in(pmt::mp("from tap"));
    set_msg_handler(pmt::mp("from tap"), boost::bind(&ether_encap_impl::from_tap, this, _1));
    message_port_register_in(pmt::mp("from wifi"));
    set_msg_handler(pmt::mp("from wifi"), boost::bind(&ether_encap_impl::from_wifi, this, _1));
    
    //Read in mac for echo filtering in debug.
    
    for(int i = 0; i < src_mac.size(); i++) {
        d_src_mac[i] = src_mac[i];
        std::cout<<"mac: " << src_mac[i] << std::endl;
    }
}

void
ether_encap_impl::from_wifi(pmt::pmt_t msg) {

    //  this is the message from the mac.cc block
    msg = pmt::cdr(msg);

    int data_len = pmt::blob_length(msg);

    //  this data HAS THE 14 bytes of ethernet header
    uint8_t * data = (uint8_t *) pmt::blob_data(msg);

    //  print out the ethernet header
    std::cout << "\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;

    std::cout << "this is the packet of len " << data_len << " in the from_wifi function " << std::endl;

//    print_mac_header(mhdr);

    investigate_packet(data + 14);


    std::cout << "\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;


//    pmt::pmt_t blob = pmt::make_blob(msg);
    message_port_pub(pmt::mp("to tap"), pmt::cons(pmt::PMT_NIL, msg));

}


void
ether_encap_impl::from_tap(pmt::pmt_t msg) {
    size_t len = pmt::blob_length(pmt::cdr(msg));
    const char *data = static_cast<const char *>(pmt::blob_data(pmt::cdr(msg)));

    //  print out the ethernet header
    std::cout << "\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;

    std::cout << "this is the packet of len " << len << " in the from_tap function" << std::endl;

    investigate_packet((uint8_t *) (data + sizeof(ethernet_header)));

    std::cout << "\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;

    const ethernet_header *ehdr = reinterpret_cast<const ethernet_header *>(data);

    //	this is actually 0x0800 in the spec, but on little endian, this reverses
    //  note that ethernet follows big endian byte order for the network, as opposed to wifi
    switch (ntohs(ehdr->type)) {
        case 0x0800: {
//            std::cout << "ether type: IP" << std::endl;

            char *buf = static_cast<char *>(malloc(len + 8 - sizeof(ethernet_header)));

            //	ethernet header stripped, 8 bytes of LLC header added, must be ieee 802.11 header?
            buf[0] = 0xaa;
            buf[1] = 0xaa;
            buf[2] = 0x03;
            buf[3] = 0x00;
            buf[4] = 0x00;
            buf[5] = 0x00;
            buf[6] = 0x08;
            buf[7] = 0x00;

            std::memcpy(buf + 8, data + sizeof(ethernet_header), len - sizeof(ethernet_header));

            pmt::pmt_t blob = pmt::make_blob(buf, len + 8 - sizeof(ethernet_header));
            message_port_pub(pmt::mp("to wifi"), pmt::cons(pmt::PMT_NIL, blob));
            break;
        }
        case 0x0806:
//            std::cout << "ether type: ARP " << std::endl;
            break;
        default:
//            std::cout << "unknown ether type" << std::endl;
            break;
    }


}

void ether_encap_impl::investigate_packet(uint8_t *data) {

    print_ipv4(data);

    struct iphdr *iph = (struct iphdr *) (data);

    uint8_t ihl = iph->ihl;

    uint8_t * transport_payload = (uint8_t *) (data + ihl * 4);

    switch (iph->protocol) {

        case 1: {
            //  this is ICMP
            handle_icmp(transport_payload, ihl, ntohs(iph->tot_len));
            break;
        }

        case 6: {
            //  this is TCP
            handle_tcp(transport_payload, ihl, ntohs(iph->tot_len));
            break;
        }

        case 17: {
            //  this is UDP
            handle_udp(transport_payload);
            break;
        }

        default:
            printf("\n\tnot TCP or IP!!\n");
            break;
    }


}



ether_encap::sptr
ether_encap::make(bool debug, std::vector<uint8_t> src_mac) {
    return gnuradio::get_initial_sptr(new ether_encap_impl(debug, src_mac));
}

