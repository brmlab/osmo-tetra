#ifndef PCAP_H
#define PCAP_H
#include <inttypes.h>

typedef uint32_t guint32;
typedef uint16_t guint16;
typedef int32_t gint32;

typedef struct __attribute__ ((__packed__)) pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
} pcap_hdr_t;

typedef struct __attribute__ ((__packed__)) pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_MAJOR 2
#define PCAP_MINOR 4
#define PCAP_SNAPLEN 65535
#define PCAP_ETHERNET 1

unsigned char fake_frame_header[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Ethernet frame, dst and src MAC
	0x08, 0x00,		// EtherType 0800 = IPv4
	0x45,			// IPv4 (0x4_), 20B header (0x_5)
	0x00,			// no diffserv
	0x00, 0xff,		// length
	0xc6, 0xd1,		// some random frag
	0x40, 0x00,		// don't frag
	0x3f,			// TTL
	0x11,			// IP proto = UDP
	0x00, 0x00,		// checksum
	0x7f, 0x00, 0x00, 0x01,	// src = 127.0.0.1
	0x7f, 0x00, 0x00, 0x01, // dst = 127.0.0.1
	0xbb, 0x13,		// source port
	0x12, 0x79,		// dst port = 4729
	0x00, 0xeb,		// length = iplen-20
	0x00, 0x00		// checksum
};
#endif
