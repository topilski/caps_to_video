// Copyright (c) 2016 Alexandr Topilski. All rights reserved.

#ifdef WIN32
#else
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <pcap.h>
#endif

#include <libavformat/avformat.h>
#include <libavutil/intreadwrite.h>
#include "media/media_stream_output.h"
#include "media/nal_units.h"

const char* outfilename = "out.mp4";  // use ffmpeg -i out.mp4.data out2.mp4
                                      // because media_stream_write_video_frame writes frame by frame
const char* infilename = "full.pcap";
const uint32_t height = 480;
const uint32_t width = 640;
const uint32_t fps = 25;
const uint32_t bit_rate = 90000;

#define SPS_KEY_HEADER "sprop-parameter-sets"
#define MARKER "\r\n"

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

const uint8_t nal_header[] = { 0x00, 0x00, 0x01 };

size_t make_nal_frame_header(const uint8_t* data, size_t data_len, const uint8_t* hdata, size_t hdata_len, uint8_t** out_nal) {
  size_t size_nal = sizeof(nal_header) + data_len;
  uint8_t* nal_data = (uint8_t*)calloc(size_nal, sizeof(uint8_t));
  memcpy(nal_data, hdata, hdata_len);
  memcpy(nal_data + hdata_len, data, data_len);
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

  media_stream_t* ostream = alloc_video_stream(outfilename, &params, 0);
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
    packet += sizeof(struct vgem_hdr);
    bpf_u_int32 packet_len = header.caplen - sizeof(struct vgem_hdr);
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
    if (!(ip->protocol != IPPROTO_UDP || ip->protocol != IPPROTO_TCP)) {
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

    if (ip->protocol == IPPROTO_UDP) {
        if (packet_len < sizeof(struct udphdr)) {
          pcap_close(pcap);
          free_video_stream(ostream);
          return EXIT_FAILURE;
        }

        packet += sizeof(struct udphdr);
        packet_len -= sizeof(struct udphdr);

        struct rtp_hdr* rtp = (struct rtp_hdr*)packet;
        if (packet_len < sizeof(struct rtp_hdr)) {
          pcap_close(pcap);
          free_video_stream(ostream);
          return EXIT_FAILURE;
        }

        // rtp payload
        packet += sizeof(struct rtp_hdr);
        packet_len -= sizeof(struct rtp_hdr);
        if (packet_len <= 2) {
          continue;
        }

        uint8_t nal = packet[0];
        uint8_t fragment_type = (nal & 0x1F);

        if (fragment_type >= 1 && fragment_type <= 23) {
          uint8_t* nal_data = NULL;
          size_t size_nal = make_nal_frame_header(packet, packet_len, nal_header, sizeof(nal_header), &nal_data);
          media_stream_write_video_frame(ostream, nal_data, size_nal);
          free(nal_data);
        } else if(fragment_type == 24) {
            packet++;
            packet_len--;
            // first we are going to figure out the total size....
            {
              int total_length= 0;
              uint8_t* dst = NULL;

              int pass;
              for(pass = 0; pass < 2; pass++) {
                  const uint8_t* src = packet;
                  int src_len = packet_len;

                  do {
                      uint16_t nal_size = AV_RB16(src); // this going to be a problem if unaligned (can it be?)

                      // consume the length of the aggregate...
                      src += 2;
                      src_len -= 2;

                      if (nal_size <= src_len) {
                          if(pass==0) {
                              // counting...
                              total_length+= sizeof(nal_header)+nal_size;
                          } else {
                              // copying
                              assert(dst);
                              memcpy(dst, nal_header, sizeof(nal_header));
                              dst += sizeof(nal_header);
                              memcpy(dst, src, nal_size);
                              dst += nal_size;
                          }
                      } else {
                          av_log(NULL, AV_LOG_ERROR,
                                 "nal size exceeds length: %d %d\n", nal_size, src_len);
                      }

                      // eat what we handled...
                      src += nal_size;
                      src_len -= nal_size;

                      if (src_len < 0)
                          av_log(NULL, AV_LOG_ERROR,
                                 "Consumed more bytes than we got! (%d)\n", src_len);
                  } while (src_len > 2);      // because there could be rtp padding..

                  if (pass == 0) {
                    dst = (uint8_t*)calloc(total_length, sizeof(uint8_t));
                  } else {
                  }
              }

          }
        } else if (fragment_type == 28 || fragment_type == 29) {
          packet++;
          packet_len--;

          uint8_t fu_indicator = nal;
          uint8_t fu_header = *packet;   // read the fu_header.
          uint8_t start_bit = fu_header >> 7;
          uint8_t end_bit = (fu_header & 0x40) >> 6;
          uint8_t nal_type = (fu_header & 0x1f);
          uint8_t reconstructed_nal = fu_indicator & (0xe0);  // the original nal forbidden bit and NRI are stored in this packet's nal;
          reconstructed_nal |= nal_type;

          packet++;
          packet_len--;

          if (fragment_type == 29) {
            packet = packet + 2;
            packet_len -= 2;
          }

          CHECK(packet_len > 0);

          if (start_bit) {
            size_t size_nal = sizeof(nal_header) + sizeof(nal) + packet_len;
            uint8_t* nal_data = (uint8_t*)calloc(size_nal, sizeof(uint8_t));
            memcpy(nal_data, nal_header, sizeof(nal_header));
            nal_data[sizeof(nal_header)]= reconstructed_nal;
            memcpy(nal_data + sizeof(nal_header) + sizeof(nal), packet, packet_len);
            media_stream_write_video_frame(ostream, nal_data, size_nal);
            free(nal_data);
          } else {
            media_stream_write_video_frame(ostream, packet, packet_len);
          }
        } else {
          NOTREACHED();
        }

        // http://stackoverflow.com/questions/3493742/problem-to-decode-h264-video-over-rtp-with-ffmpeg-libavcodec
        // http://stackoverflow.com/questions/1957427/detect-mpeg4-h264-i-frame-idr-in-rtp-stream
    } else if (ip->protocol == IPPROTO_TCP) {
        if (packet_len < sizeof(struct tcphdr)) {
          continue;
        }

        struct tcphdr *tcpheader = (struct tcphdr *)packet;
        packet += sizeof(struct tcphdr);
        packet_len -= sizeof(struct tcphdr);

        if (packet_len < sizeof(struct rtp_hdr)) {
          continue;
        }

        const char* start_sps = strstr((const char*)packet, SPS_KEY_HEADER);
        if (start_sps) {
          const char* value = start_sps + sizeof(SPS_KEY_HEADER);
          const char* end = strstr((const char*)value, MARKER);
          if (end) {
            size_t len = end - value;
            size_t i;
            for (i = 0; i < len; ++i) {
              char c = value[i];
              if (c == ',') {
                uint8_t* nal_data = NULL;
                size_t dec_sps_len = 0;
                uint8_t* dec_sps = base64_decode((const uint8_t*)value, i, &dec_sps_len);    // alloc
                size_t size_nal = make_nal_frame_header((const uint8_t*)dec_sps, dec_sps_len, nal_header, sizeof(nal_header), &nal_data);
                media_stream_write_video_frame(ostream, nal_data, size_nal);
                free(dec_sps);

                nal_data = NULL;
                size_t start_pps_pos = i + 1;
                size_t dec_pps_len = 0;
                uint8_t* dec_pps = base64_decode((const uint8_t*)value + start_pps_pos, len - start_pps_pos, &dec_pps_len);  // alloc
                size_nal = make_nal_frame_header((const uint8_t*)dec_pps, dec_pps_len, nal_header, sizeof(nal_header), &nal_data);
                media_stream_write_video_frame(ostream, nal_data, size_nal);
                free(dec_pps);
                break;
              }
            }
          }
        }
        // parse RTSP packet
    }
  }


  pcap_close(pcap);
  free_video_stream(ostream);
  return EXIT_SUCCESS;
}
