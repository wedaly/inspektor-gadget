// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <sys/socket.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "dns-common.h"

#define DNS_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))

const int DNS_CLASS_IN = 1;   // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4

const int DNS_TYPE_A = 1;     // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
const int DNS_TYPE_AAAA = 28; // https://www.rfc-editor.org/rfc/rfc3596#section-2.1

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

// we need this to make sure the compiler doesn't remove our struct
const struct event_t *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
union dnsflags {
	struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		__u8 rcode :4;	// response code
		__u8 z :3;	// reserved
		__u8 ra :1;	// recursion available
		__u8 rd :1;	// recursion desired
		__u8 tc :1;	// truncation
		__u8 aa :1;	// authoritive answer
		__u8 opcode :4;	// kind of query
		__u8 qr :1;	// 0=query; 1=response
#elif __BYTE_ORDER == __ORDER_BIG_ENDIAN__
		__u8 qr :1;	// 0=query; 1=response
		__u8 opcode :4;	// kind of query
		__u8 aa :1;	// authoritive answer
		__u8 tc :1;	// truncation
		__u8 rd :1;	// recursion desired
		__u8 ra :1;	// recursion available
		__u8 z :3;	// reserved
		__u8 rcode :4;	// response code
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif
	};
	__u16 flags;
};

struct dnshdr {
	__u16 id;

	union dnsflags flags;

	__u16 qdcount; // number of question entries
	__u16 ancount; // number of answer entries
	__u16 nscount; // number of authority records
	__u16 arcount; // number of additional records
};

// DNS question
// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
struct dnsq {
	__u16 qname;
	__u16 qtype;
	__u16 qclass;
}

// DNS resource record
// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3 
struct dnsrr {
	__u16 name;
	__u16 type;
	__u16 class;
	__u16 ttl;
	__u16 rdlength;
	// followed by rdata (rdlength bytes)
}

static __u32 dns_name_length(struct __sk_buff *skb) {
	// This loop iterates over the DNS labels to find the total DNS name length.
	unsigned int i;
	unsigned int skip = 0;
	for (i = 0; i < MAX_DNS_NAME ; i++) {
		if (skip != 0) {
			skip--;
		} else {
			int label_len = load_byte(skb, DNS_OFF + sizeof(struct dnshdr) + i);
			if (label_len == 0)
				break;
			// The simple solution "i += label_len" gives verifier
			// errors, so work around with skip.
			skip = label_len;
		}
	}

	return i < MAX_DNS_NAME ? i : MAX_DNS_NAME;
}

static struct event_t build_event(struct __sk_buff *skb, union dnsflags flags, __u32 name_len, __u16 ancount) {
	struct event_t event = {0,};

	event.id = load_half(skb, DNS_OFF + offsetof(struct dnshdr, id));
	event.af = AF_INET;
	event.daddr_v4 = load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));
	event.saddr_v4 = load_word(skb, ETH_HLEN + offsetof(struct iphdr, saddr));
	// load_word converts from network to host endianness. Convert back to
	// network endianness because inet_ntop() requires it.
	event.daddr_v4 = bpf_htonl(event.daddr_v4);
	event.saddr_v4 = bpf_htonl(event.saddr_v4);

	event.qr = flags.qr;

	if (flags.qr == 1) {
		// Response code set only for replies.
		event.rcode = flags.rcode;
	}

	bpf_skb_load_bytes(skb, DNS_OFF + sizeof(struct dnshdr), event.name, name_len);

	event.pkt_type = skb->pkt_type;

	// Read QTYPE right after the QNAME
	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
	event.qtype = load_half(skb, DNS_OFF + sizeof(struct dnshdr) + name_len + 1);

	if ancount > 0 {
		event.ancount = ancount;

		int ans_offset = DNS_OFF + sizeof(struct dnshdr) + name_len + sizeof(dnsq));
		__u16 rrtype = load_half(skb, ans_offset + offsetof(struct dnsrr, type);
		__u16 rrclass = load_half(skb, ans_offset + offsetof(struct dnsrr, class);

		if (rrtype == DNS_TYPE_A && rrclass == DNS_CLASS_IN) {
			bpf_skb_load_bytes(skb, ans_offset + sizeof(dnsrr), event.first_addr_v4, 4);
		} else if (rrtype == DNS_TYPE_AAAA && rrclass == DNS_CLASS_IN) {
			bpf_skb_load_bytes(skb, ans_offset + sizeof(dnsrr), event.first_addr_v6, 8);
		}
	}

	return event;
}

SEC("socket1")
int ig_trace_dns(struct __sk_buff *skb)
{
	// Skip non-IP packets
	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
		return 0;

	// Skip non-UDP packets
	if (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) != IPPROTO_UDP)
		return 0;

	union dnsflags flags;
	flags.flags = load_half(skb, DNS_OFF + offsetof(struct dnshdr, flags));

	// Skip DNS packets with more than 1 question
	if (load_half(skb, DNS_OFF + offsetof(struct dnshdr, qdcount)) != 1)
		return 0;

	__u16 ancount = load_half(skb, DNS_OFF + offsetof(struct dnshdr, ancount));
	__u16 nscount = load_half(skb, DNS_OFF + offsetof(struct dnshdr, nscount));

	// Skip DNS queries with answers
	if ((flags.qr == 0) && (ancount + nscount != 0))
		return 0;

	__u32 len = dns_name_length(skb);
	if  (len == 0)
		return 0;

	struct event_t event = build_event(skb, flags, len, ancount);
	bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

char _license[] SEC("license") = "GPL";
