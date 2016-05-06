// Copyright (c) 2016 Alexandr Topilski. All rights reserved.

#ifdef WIN32
#else
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <netinet/tcp.h>
#endif

extern "C" {
#include <libavformat/avformat.h>
#include "media/media_stream_output.h"
}

const char* outfilename = "out.mp4";
const char* infilename = "in.pcap";

int main(int argc, char *argv[]) {
  av_register_all();

  media_stream_params_t params;
  params.height_video = 800;
  params.width_video = 1024;
  params.video_fps = 25;
  params.bit_stream = 90000;
  params.codec_id = AV_CODEC_ID_H264;

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
    bpf_u_int32 capture_len = header.caplen;
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

    struct ip* ip = (struct ip*) packet;
    unsigned int IP_header_length = ip->ip_hl * 4;  /* ip_hl is in 4-byte words */
    if (capture_len < IP_header_length) { /* didn't capture the full IP header including options */
      pcap_close(pcap);
      free_video_stream(ostream);
      return EXIT_FAILURE;
    }

    packet += IP_header_length;
    capture_len -= IP_header_length;
    if (capture_len < sizeof(struct tcphdr)) {
      pcap_close(pcap);
      free_video_stream(ostream);
      return EXIT_FAILURE;
    }

    packet += sizeof(struct tcphdr);
    capture_len -= sizeof(struct tcphdr);

    media_stream_write_video_frame(ostream, packet, capture_len);
  }

  pcap_close(pcap);
  free_video_stream(ostream);
  return EXIT_SUCCESS;
}
