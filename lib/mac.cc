/*
 * Copyright (C) 2013, 2016 Bastian Bloessl <bloessl@ccs-labs.org>
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
#include <ieee802-11/mac.h>

#include <gnuradio/io_signature.h>
#include <gnuradio/block_detail.h>

#include "utils.h"

#if defined(__APPLE__)
#include <architecture/byte_order.h>
#define htole16(x) OSSwapHostToLittleInt16(x)
#else
#include <endian.h>
#endif

#include <boost/crc.hpp>
#include <iostream>
#include <stdexcept>

using namespace gr::ieee802_11;

class mac_impl : public mac {

public:

mac_impl(std::vector<uint8_t> src_mac, std::vector<uint8_t> dst_mac, std::vector<uint8_t> bss_mac, bool debug) :
		block("mac",
			gr::io_signature::make(0, 0, 0),
			gr::io_signature::make(0, 0, 0)),
        d_debug(debug),
        d_seq_nr(0),
        d_last_seq(0)
{

	message_port_register_out(pmt::mp("phy out"));
	message_port_register_out(pmt::mp("app out"));

	message_port_register_in(pmt::mp("app in"));
	set_msg_handler(pmt::mp("app in"), boost::bind(&mac_impl::app_in, this, _1));

	message_port_register_in(pmt::mp("phy in"));
	set_msg_handler(pmt::mp("phy in"), boost::bind(&mac_impl::phy_in, this, _1));

	if(!check_mac(src_mac)) throw std::invalid_argument("wrong mac address size");
	if(!check_mac(dst_mac)) throw std::invalid_argument("wrong mac address size");
	if(!check_mac(bss_mac)) throw std::invalid_argument("wrong mac address size");

	for(int i = 0; i < 6; i++) {
		d_src_mac[i] = src_mac[i];
		d_dst_mac[i] = dst_mac[i];
		d_bss_mac[i] = bss_mac[i];
	}
}

void phy_in (pmt::pmt_t msg) {
	// this must be a pair
	if (!pmt::is_blob(pmt::cdr(msg))) {
		throw std::runtime_error("PMT must be blob");
	}

    //  get a reference to the actual bytes
    msg = pmt::cdr(msg);

    int data_len = pmt::blob_length(msg);


    const mac_header *mhdr = reinterpret_cast<const mac_header *>(pmt::blob_data(msg));


    //  TODO: wifi seq_nr
    if (d_last_seq == mhdr->seq_nr) {
        dout << "Ether Encap: frame already seen -- skipping" << std::endl;
        return;
    }

    d_last_seq = mhdr->seq_nr;

    if (data_len < 33) {
        dout << "Ether Encap: frame too short to parse (<33)" << std::endl;
        return;
    }

    //  source mac of the frame has to be equal to some other mac address, else it's an echo
    if ( check_mac_eq(mhdr->addr2, d_src_mac) ) {
        std::cout << "#notmypacket" << std::endl;
        return;
    }

    // this is more than needed
    char *buf = static_cast<char *>(std::malloc(data_len + sizeof(ethernet_header)));
    ethernet_header *ehdr = reinterpret_cast<ethernet_header *>(buf);

    if (((mhdr->frame_control >> 2) & 3) != 2) {
        std::cout << "this is not a data frame -- ignoring" << std::endl;
        return;
    }

    //  add the 14 bytes of ethernet header to buf
    std::memcpy(ehdr->dest, mhdr->addr1, 6);
    std::memcpy(ehdr->src, mhdr->addr2, 6);
    ehdr->type = 0x0008;

    char *frame = (char *) pmt::blob_data(msg);

    // DATA
    if ((((mhdr->frame_control) >> 2) & 63) == 2) {

        //	strip 802.11 header, add wired 802.11 header for tun/tap interface
        memcpy(buf + sizeof(ethernet_header), frame + 32, data_len - 32);
        pmt::pmt_t payload = pmt::make_blob(buf, data_len - 32 + 14);
        message_port_pub(pmt::mp("app out"), pmt::cons(pmt::PMT_NIL, payload));

        // QoS Data
    } else if ((((mhdr->frame_control) >> 2) & 63) == 34) {

        //	strip 802.11 header, add wired 802.11 header for tun/tap interface
        memcpy(buf + sizeof(ethernet_header), frame + 34, data_len - 34);
        pmt::pmt_t payload = pmt::make_blob(buf, data_len - 34 + 14);
        message_port_pub(pmt::mp("app out"), pmt::cons(pmt::PMT_NIL, payload));
    }

    free(buf);


//	pmt::pmt_t blob(pmt::cdr(msg));
//	const char *mpdu = reinterpret_cast<const char *>(pmt::blob_data(blob));
////	std::cout << "pdu len " << pmt::blob_length(blob) << std::endl;
//	pmt::pmt_t msdu = pmt::make_blob(mpdu + 24, pmt::blob_length(blob) - 24);
//
////	message_port_pub(pmt::mp("app out"), pmt::cons(pmt::car(msg), msdu));
}

void app_in (pmt::pmt_t msg) {

	size_t       msg_len;
	const char   *msdu;
	std::string  str;

	//	at this point, msg contains the LLC header only. ethernet header is stripped out in ether_encap_impl
	if(pmt::is_symbol(msg)) {

		str = pmt::symbol_to_string(msg);
		msg_len = str.length();
		msdu = str.data();

	} else if(pmt::is_pair(msg)) {

		msg_len = pmt::blob_length(pmt::cdr(msg));
		msdu = reinterpret_cast<const char *>(pmt::blob_data(pmt::cdr(msg)));

	} else {
		throw std::invalid_argument("MAC expects PDUs or strings");
		return;
	}

	if(msg_len > MAX_PAYLOAD_SIZE) {
		throw std::invalid_argument("Frame too large (> 1500)");
	}

	// make MAC frame
	int    psdu_length;
	generate_mac_data_frame(msdu, msg_len, &psdu_length);

	// dict
	pmt::pmt_t dict = pmt::make_dict();
	dict = pmt::dict_add(dict, pmt::mp("crc_included"), pmt::PMT_T);

	// blob
	pmt::pmt_t mac = pmt::make_blob(d_psdu, psdu_length);

	// pdu
	message_port_pub(pmt::mp("phy out"), pmt::cons(dict, mac));
}

void generate_mac_data_frame(const char *msdu, int msdu_size, int *psdu_size) {

	// mac header
	mac_header header;

    //  802.11 follows little endian byte order
    //  the diagrams showing the frame layout have bit order increasing from left to right, even in multi-byte fields
    //  the LSByte is version/type/subtype, the MSByte is flags
    //  the byte with lower memory address is sent out on the wire first
    //  in wireshark display, the memory addresses increase from left to right. so the first byte you see is the LSByte
    //  so wireshark will show you 0x0800 as the frame control field
    //  see http://www.cas.mcmaster.ca/~rzheng/course/CAS765fa13/hw3.pdf

	header.frame_control = htole16(0x0008);
	header.duration = htole16(0x0000);

	for(int i = 0; i < 6; i++) {
		header.addr1[i] = d_dst_mac[i];
		header.addr2[i] = d_src_mac[i];
		header.addr3[i] = d_bss_mac[i];
	}

	header.seq_nr = 0;
	for (int i = 0; i < 12; i++) {
		if(d_seq_nr & (1 << i)) {
			header.seq_nr |=  (1 << (i + 4));
		}
	}
	header.seq_nr = htole16(header.seq_nr);
	d_seq_nr++;

	//header size is 24 (mac_header), plus 4 for FCS means 28 bytes
	*psdu_size = sizeof(mac_header) + 4 + msdu_size;

	//copy mac header into psdu
	std::memcpy(d_psdu, &header, 24);
	//copy msdu into psdu
	memcpy(d_psdu + 24, msdu, msdu_size);
	//compute and store fcs
	boost::crc_32_type result;
	result.process_bytes(d_psdu, msdu_size + 24);

	uint32_t fcs = result.checksum();
	memcpy(d_psdu + msdu_size + 24, &fcs, sizeof(uint32_t));
}

bool check_mac(std::vector<uint8_t> mac) {
	if(mac.size() != 6) return false;
	return true;
}

private:
	uint16_t d_seq_nr;
    uint16_t d_last_seq;
    bool d_debug;
    uint8_t d_src_mac[6];
	uint8_t d_dst_mac[6];
	uint8_t d_bss_mac[6];
	uint8_t d_psdu[MAX_PSDU_SIZE];
};

mac::sptr
mac::make(std::vector<uint8_t> src_mac, std::vector<uint8_t> dst_mac, std::vector<uint8_t> bss_mac, bool debug) {
	return gnuradio::get_initial_sptr(new mac_impl(src_mac, dst_mac, bss_mac, debug));
}

