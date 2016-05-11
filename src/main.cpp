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
#include "media/nal_units.h"
}

const char* outfilename = "out.mp4";
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

struct h264_hdr {
  uint8_t fu_iden;
  uint8_t fu_hdr;
};

typedef struct {
  unsigned char type:5;
  unsigned char nri:2;
  unsigned char f:1;
} nal_unit_header;

typedef struct {
  unsigned char type:5;
  unsigned char r:1;
  unsigned char e:1;
  unsigned char s:1;
} fu_header;

struct fu_a_packet{
  nal_unit_header nh;
  fu_header fuh;
  unsigned char* payload;
};

const uint8_t idr_header[] = { 0x00, 0x00, 0x01 };

size_t make_nal_frame(const uint8_t* data, size_t data_len, uint8_t** out_nal) {
  size_t size_nal = sizeof(idr_header) + data_len;
  uint8_t* nal_data = (uint8_t*)calloc(size_nal, sizeof(uint8_t));
  memcpy(nal_data, idr_header, sizeof(idr_header));
  memcpy(nal_data + sizeof(idr_header), data, data_len);
  *out_nal = nal_data;
  return size_nal;
}

int main(int argc, char *argv[]) {
  av_register_all();

  media_stream_params_t params;
  params.height_video = height;
  params.width_video = width;
  params.video_fps = fps;
  params.bit_stream = bit_rate;
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
    packet += sizeof(vgem_hdr);
    bpf_u_int32 packet_len = header.caplen - sizeof(vgem_hdr);
    if (packet_len < sizeof(struct ether_header)) {
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
    packet_len -= sizeof(struct ether_header);

    if (packet_len < sizeof(struct ip)) {
      pcap_close(pcap);
      free_video_stream(ostream);
      return EXIT_FAILURE;
    }

    struct iphdr* ip = (struct iphdr*) packet;
    if (ip->protocol != IPPROTO_UDP) {
      continue;
    }

    unsigned int IP_header_length = ip->ihl * 4;  /* ip_hl is in 4-byte words */
    if (packet_len < IP_header_length) { /* didn't capture the full IP header including options */
      pcap_close(pcap);
      free_video_stream(ostream);
      return EXIT_FAILURE;
    }

    packet += IP_header_length;
    packet_len -= IP_header_length;

    if (packet_len < sizeof(udphdr)) {
      pcap_close(pcap);
      free_video_stream(ostream);
      return EXIT_FAILURE;
    }

    packet += sizeof(udphdr);
    packet_len -= sizeof(udphdr);

    if (packet_len < sizeof(rtp_hdr)) {
      pcap_close(pcap);
      free_video_stream(ostream);
      return EXIT_FAILURE;
    }

    // rtp payload
    packet += sizeof(rtp_hdr);
    packet_len -= sizeof(rtp_hdr);
    if (packet_len <= 2) {
      continue;
    }

    size_t offset = 0;
    uint8_t nal = packet[0];
    int fragment_type = nal & 0x1F;
    uint8_t fu_header = packet[1];
    int nal_type = fu_header & 0x1F;
    int start_bit = fu_header >> 7;
    int end_bit = (fu_header & 0x40) >> 6;
    if (fragment_type == 28) {
      int fragment_size = packet_len - 2;
      if (fragment_size > 0) {
        //If the start bit was set
        const uint8_t* payload = packet + 2;
        if (start_bit) {
          uint8_t fu_indicator = nal;
          uint8_t reconstructed_nal = fu_indicator & (0xE0);
          reconstructed_nal |= nal_type;

          size_t size_nal = sizeof(idr_header) + sizeof(nal) + fragment_size;
          uint8_t* nal_data = (uint8_t*)calloc(size_nal, sizeof(uint8_t));
          memcpy(nal_data, idr_header, sizeof(idr_header));
          nal_data[sizeof(idr_header)]= reconstructed_nal;
          memcpy(nal_data + sizeof(idr_header) + sizeof(nal), payload, fragment_size);
          media_stream_write_video_frame(ostream, nal_data, size_nal);
          free(nal_data);
        } else {
          media_stream_write_video_frame(ostream, payload, fragment_size);
        }
      } else {
        NOTREACHED();
      }
    } else if (fragment_type >= 1 && fragment_type <= 23) {
      if (fragment_type > 5) {
        if (fragment_type == NAL_UNIT_TYPE_SEI) {  //sei
        } else if (fragment_type == NAL_UNIT_TYPE_SPS) {  // sps
        } else if (fragment_type == NAL_UNIT_TYPE_PPS) {  // pps
        }
      }

      uint8_t* nal_data = NULL;
      size_t size_nal = make_nal_frame(packet, packet_len, &nal_data);
      media_stream_write_video_frame(ostream, nal_data, size_nal);
      free(nal_data);
    } else if(fragment_type == 24) {
      NOTREACHED();
    } else if(fragment_type == 29) {
      //NOTREACHED();
    } else {
      NOTREACHED();
    }

    // http://stackoverflow.com/questions/3493742/problem-to-decode-h264-video-over-rtp-with-ffmpeg-libavcodec
    // http://stackoverflow.com/questions/1957427/detect-mpeg4-h264-i-frame-idr-in-rtp-stream
  }


  pcap_close(pcap);
  free_video_stream(ostream);
  return EXIT_SUCCESS;
}
