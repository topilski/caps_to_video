// Copyright (c) 2016 Alexandr Topilski. All rights reserved.

#ifdef WIN32
#else
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <pcap.h>
#endif

extern "C" {
#include <libavformat/avformat.h>
#include "media/media_stream_output.h"
}

const char* outfilename = "out.mpg";
const char* infilename = "full.pcap";
const uint32_t height = 800;
const uint32_t width = 1024;
const uint32_t fps = 25;
const uint32_t bit_rate = 90000;

struct vgem_hdr {
  int8_t data[12];
};

#pragma pack(1)
struct rtp_hdr {
#if __BYTE_ORDER == __BIG_ENDIAN
  //For big endian
  unsigned char version:2;       // Version, currently 2
  unsigned char padding:1;       // Padding bit
  unsigned char extension:1;     // Extension bit
  unsigned char cc:4;            // CSRC count
  unsigned char marker:1;        // Marker bit
  unsigned char payload:7;       // Payload type
#else
  //For little endian
  unsigned char cc:4;            // CSRC count
  unsigned char extension:1;     // Extension bit
  unsigned char padding:1;       // Padding bit
  unsigned char version:2;       // Version, currently 2
  unsigned char payload:7;       // Payload type
  unsigned char marker:1;        // Marker bit
#endif

  uint16_t sequence;        // sequence number
  uint32_t timestamp;       //  timestamp
  uint32_t sources;      // contributing sources
};
#pragma pack()

struct rtp_ext_hdr {
  uint16_t profile_data; // Profile data
  uint16_t length;  //Length
};

int main(int argc, char *argv[]) {
  av_register_all();

  media_stream_params_t params;
  params.height_video = height;
  params.width_video = width;
  params.video_fps = fps;
  params.bit_stream = bit_rate;
  params.codec_id = AV_CODEC_ID_MPEG2VIDEO;

  media_stream_t* ostream = alloc_video_stream(outfilename, &params, false);
  if(!ostream){
    return EXIT_FAILURE;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* pcap = pcap_open_offline_with_tstamp_precision(infilename, PCAP_TSTAMP_PRECISION_NANO, errbuf);
  if (!pcap) {
    fprintf(stderr, "error reading pcap file: %s\n", errbuf);
    free_video_stream(ostream);
    return EXIT_FAILURE;
  }

  struct pcap_pkthdr header;
  const u_char *packet;
  while ((packet = pcap_next(pcap, &header)) != NULL) {
    packet += sizeof(vgem_hdr);
    bpf_u_int32 capture_len = header.caplen - sizeof(vgem_hdr);
    if (capture_len < sizeof(struct ether_header)) {
      pcap_close(pcap);
      free_video_stream(ostream);
      return EXIT_FAILURE;
    }

    struct ether_header* ethernet_header = (struct ether_header*)packet;
    uint16_t ht = ntohs(ethernet_header->ether_type);
    if (ht != ETHERTYPE_IP) {
      continue;
    }

    /* Skip over the Ethernet header. (14)*/
    packet += sizeof(struct ether_header);
    capture_len -= sizeof(struct ether_header);

    if (capture_len < sizeof(struct ip)) {
      pcap_close(pcap);
      free_video_stream(ostream);
      return EXIT_FAILURE;
    }

    struct iphdr* ip = (struct iphdr*) packet;
    if (ip->protocol != IPPROTO_UDP) {
      continue;
    }

    unsigned int IP_header_length = ip->ihl * 4;  /* ip_hl is in 4-byte words */
    if (capture_len < IP_header_length) { /* didn't capture the full IP header including options */
      pcap_close(pcap);
      free_video_stream(ostream);
      return EXIT_FAILURE;
    }

    packet += IP_header_length;
    capture_len -= IP_header_length;

    if (capture_len < sizeof(udphdr)) {
      pcap_close(pcap);
      free_video_stream(ostream);
      return EXIT_FAILURE;
    }

    packet += sizeof(udphdr);
    capture_len -= sizeof(udphdr);

    struct rtp_hdr* rtp = (struct rtp_hdr*) packet;
    if (capture_len < sizeof(rtp_hdr)) {
      pcap_close(pcap);
      free_video_stream(ostream);
      return EXIT_FAILURE;
    }

    // rtp payload
    packet += sizeof(rtp_hdr);
    capture_len -= sizeof(rtp_hdr);
    media_stream_write_video_frame(ostream, packet, capture_len);
  }

  pcap_close(pcap);
  free_video_stream(ostream);
  return EXIT_SUCCESS;
}
