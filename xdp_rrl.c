#include <linux/bpf.h>
#include <linux/if_ether.h> /* for struct ethhdr   */
#include <linux/ip.h>       /* for struct iphdr    */
#include <linux/ipv6.h>     /* for struct ipv6hdr  */
#include <linux/in.h>       /* for IPPROTO_UDP     */
#include <linux/udp.h>      /* for struct udphdr   */
#include "bpf_helpers.h"    /* for bpf_get_prandom_u32() */
#include "bpf_endian.h"     /* for __bpf_htons()   */

// do not use libc includes because this causes clang
// to include 32bit headers on 64bit ( only ) systems.
typedef __u8  uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
#define memcpy __builtin_memcpy

#define DNS_PORT      53

#define FRAME_SIZE	  1000000000
#define THRESHOLD	  2

struct config {
        uint16_t ratelimit;
        uint8_t numcpus;
} __attribute__((packed));

static volatile const struct config CFG;
#define cfg (&CFG)

/*
 *  Store the time frame
 */
struct bucket {
	uint64_t start_time;
	uint64_t n_packets;
};

#ifndef __section
# define __section(NAME) __attribute__((section(NAME), used))
#endif
#ifndef __uint
# define __uint(name, val) int(*(name))[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *(name)
#endif

struct ipv4_key {
	struct   bpf_lpm_trie_key lpm_key;
	uint8_t  ipv4[4];
};

struct {
	__uint(type,  BPF_MAP_TYPE_LPM_TRIE);
	__type(key,   struct ipv4_key);
	__type(value, uint64_t);
	__uint(max_entries, 10000);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} exclude_v4_prefixes __section(".maps");

struct ipv6_key {
	struct   bpf_lpm_trie_key lpm_key;
	uint64_t ipv6;
} __attribute__((packed));

struct {
	__uint(type,  BPF_MAP_TYPE_LPM_TRIE);
	__type(key,   struct ipv6_key);
	__type(value, uint64_t);
	__uint(max_entries, 10000);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
        __uint(map_flags, BPF_F_NO_PREALLOC);
} exclude_v6_prefixes __section(".maps");

struct {
	__uint(type,  BPF_MAP_TYPE_PERCPU_HASH);
	__type(key,   uint32_t);
	__type(value, struct bucket);
	__uint(max_entries, 1000000);
} state_map __section(".maps");

struct {
	__uint(type,  BPF_MAP_TYPE_PERCPU_HASH);
	__type(key,   sizeof(struct in6_addr));
	__type(value, struct bucket);
	__uint(max_entries, 1000000);
} state_map_v6 __section(".maps");

/** Copied from the kernel module of the base03-map-counter example of the
 ** XDP Hands-On Tutorial (see https://github.com/xdp-project/xdp-tutorial )
 *
 * LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

/*
 *  Store the VLAN header
 */
struct vlanhdr {
	uint16_t tci;
	uint16_t encap_proto;
};

/*
 *  Store the DNS header
 */
struct dnshdr {
	uint16_t id;
	union {
		struct {
			uint8_t  rd     : 1;
			uint8_t  tc     : 1;
			uint8_t  aa     : 1;
			uint8_t  opcode : 4;
			uint8_t  qr     : 1;

			uint8_t  rcode  : 4;
			uint8_t  cd     : 1;
			uint8_t  ad     : 1;
			uint8_t  z      : 1;
			uint8_t  ra     : 1;
		}        as_bits_and_pieces;
		uint16_t as_value;
	} flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

/*
 *  Helper pointer to parse the incoming packets
 */
struct cursor {
	void *pos;
	void *end;
};


/*
 *  Initializer of a cursor pointer
 */
static __always_inline
void cursor_init(struct cursor *c, struct xdp_md *ctx)
{
	c->end = (void *)(long)ctx->data_end;
	c->pos = (void *)(long)ctx->data;
}

#define PARSE_FUNC_DECLARATION(STRUCT)			\
static __always_inline						\
struct STRUCT *parse_ ## STRUCT (struct cursor *c)	\
{							\
	struct STRUCT *ret = c->pos;			\
	if (c->pos + sizeof(struct STRUCT) > c->end)	\
		return 0;				\
	c->pos += sizeof(struct STRUCT);		\
	return ret;					\
}

PARSE_FUNC_DECLARATION(ethhdr)
PARSE_FUNC_DECLARATION(vlanhdr)
PARSE_FUNC_DECLARATION(iphdr)
PARSE_FUNC_DECLARATION(ipv6hdr)
PARSE_FUNC_DECLARATION(udphdr)
PARSE_FUNC_DECLARATION(dnshdr)

/*
 * Parse ethernet frame and fill the struct
 */
static __always_inline
struct ethhdr *parse_eth(struct cursor *c, uint16_t *eth_proto)
{
	struct ethhdr  *eth;

	if (!(eth = parse_ethhdr(c)))
		return 0;

	*eth_proto = eth->h_proto;
	if (*eth_proto == __bpf_htons(ETH_P_8021Q)
	||  *eth_proto == __bpf_htons(ETH_P_8021AD)) {
		struct vlanhdr *vlan;

		if (!(vlan = parse_vlanhdr(c)))
			return 0;

		*eth_proto = vlan->encap_proto;
		if (*eth_proto == __bpf_htons(ETH_P_8021Q)
		||  *eth_proto == __bpf_htons(ETH_P_8021AD)) {
			if (!(vlan = parse_vlanhdr(c)))
				return 0;

			*eth_proto = vlan->encap_proto;
		}
	}
	return eth;
}

/*
 *  Recalculate the checksum
 */
static __always_inline
void update_checksum(uint16_t *csum, uint16_t old_val, uint16_t new_val)
{
	uint32_t new_csum_value;
	uint32_t new_csum_comp;
	uint32_t undo;

	undo = ~((uint32_t)*csum) + ~((uint32_t)old_val);
	new_csum_value = undo + (undo < ~((uint32_t)old_val)) + (uint32_t)new_val;
	new_csum_comp = new_csum_value + (new_csum_value < ((uint32_t)new_val));
	new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
	new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
	*csum = (uint16_t)~new_csum_comp;
}

static __always_inline
int do_rate_limit(struct udphdr *udp, struct dnshdr *dns, struct bucket *b)
{
	// increment number of packets
	b->n_packets++;

	// get the current and elapsed time
	uint64_t now = bpf_ktime_get_ns();
	uint64_t elapsed = now - b->start_time;

	// make sure the elapsed time is set and not outside of the frame
	if (b->start_time == 0 || elapsed >= FRAME_SIZE)
	{
		// start new time frame
		b->start_time = now;
		b->n_packets = 0;
	}

	//if (b->n_packets < THRESHOLD)
	if (b->n_packets < (cfg->ratelimit / cfg->numcpus))
		return 1;

	//bpf_printk("bounce\n");
	//save the old header values
	uint16_t old_val = dns->flags.as_value;

	// change the DNS flags
	dns->flags.as_bits_and_pieces.ad = 0;
	dns->flags.as_bits_and_pieces.qr = 1;
	dns->flags.as_bits_and_pieces.tc = 1;

	// change the UDP destination to the source
	udp->dest   = udp->source;
	udp->source = __bpf_htons(DNS_PORT);

	// calculate and write the new checksum
	update_checksum(&udp->check, old_val, dns->flags.as_value);

	// bounce
	return 0;
}

/*
 * Parse DNS ipv4 message
 * Returns 1 if message needs to go through (i.e. pass)
 *        -1 if something went wrong and the packet needs to be dropped
 *         0 if (modified) message needs to be replied
 */
static __always_inline
int udp_dns_reply_v4(struct cursor *c, uint32_t key)
{
	struct udphdr  *udp;
	struct dnshdr  *dns;

	// check that we have a DNS packet
	if (!(udp = parse_udphdr(c)) || udp->dest != __bpf_htons(DNS_PORT)
	||  !(dns = parse_dnshdr(c)))
		return 1;

	// search for the prefix in the LPM trie
	struct ipv4_key key4;
	key4.lpm_key.prefixlen = 32;
	key4.ipv4[0]   = key & 0xff;
	key4.ipv4[1]   = (key >> 8) & 0xff;
	key4.ipv4[2]   = (key >> 16) & 0xff;
	key4.ipv4[3]   = (key >> 24) & 0xff;

	uint64_t *count = bpf_map_lookup_elem(&exclude_v4_prefixes, &key4);

	// if the prefix matches, we exclude it from rate limiting
	if (count) {
		lock_xadd(count, 1);
		return 1; // XDP_PASS
	}

	// get the rrl bucket from the map by IPv4 address
	struct bucket *b = bpf_map_lookup_elem(&state_map, &key);

	// did we see this IPv4 address before?
	if (b)
		return do_rate_limit(udp, dns, b);

	// create new starting bucket for this key
	struct bucket new_bucket;
	new_bucket.start_time = bpf_ktime_get_ns();
	new_bucket.n_packets = 0;

	// store the bucket and pass the packet
	bpf_map_update_elem(&state_map, &key, &new_bucket, BPF_ANY);
	return 1; // XDP_PASS
}

/*
 * Parse DNS mesage.
 * Returns 1 if message needs to go through (i.e. pass)
 *        -1 if something went wrong and the packet needs to be dropped
 *         0 if (modified) message needs to be replied
 */
static __always_inline
int udp_dns_reply_v6(struct cursor *c, struct in6_addr *key)
{
 	struct udphdr  *udp;
 	struct dnshdr  *dns;

 	// check that we have a DNS packet
 	if (!(udp = parse_udphdr(c)) || udp->dest != __bpf_htons(DNS_PORT)
 	||  !(dns = parse_dnshdr(c)))
 		return 1;

	// search for the prefix in the LPM trie
	struct {
		uint32_t        prefixlen;
		struct in6_addr ipv6_addr;
	} key6 = {
		.prefixlen = 64,
		.ipv6_addr = *key
	};
	uint64_t *count = bpf_map_lookup_elem(&exclude_v6_prefixes, &key6);

	// if the prefix is matches, we exclude it from rate limiting
	if (count) {
		lock_xadd(count, 1);
		return 1; // XDP_PASS
	}
 	// get the rrl bucket from the map by IPv6 address
 	struct bucket *b = bpf_map_lookup_elem(&state_map_v6, key);

 	// did we see this IPv6 address before?
	if (b)
		return do_rate_limit(udp, dns, b);

	// create new starting bucket for this key
	struct bucket new_bucket;
	new_bucket.start_time = bpf_ktime_get_ns();
	new_bucket.n_packets = 0;

	// store the bucket and pass the packet
	bpf_map_update_elem(&state_map_v6, key, &new_bucket, BPF_ANY);
	return 1;
}


/*
 *  Recieve and parse request
 *  @var struct xdp_md
 */
SEC("xdp-rrl")
int xdp_rrl(struct xdp_md *ctx)
{
	// store variables
	struct cursor   c;
	struct ethhdr  *eth;
	uint16_t        eth_proto;
	struct iphdr   *ipv4;
	struct ipv6hdr *ipv6;
	int            r = 0;

	// initialise the cursor
	cursor_init(&c, ctx);
	if (!(eth = parse_eth(&c, &eth_proto)))
		return XDP_PASS;

	// differentiate the parsing of the IP header based on the version
	if (eth_proto == __bpf_htons(ETH_P_IP))
	{
		if (!(ipv4 = parse_iphdr(&c))
		||    ipv4->protocol != IPPROTO_UDP
		||   (r = udp_dns_reply_v4(&c, ipv4->saddr))) {
			return r < 0 ? XDP_ABORTED : XDP_PASS;
		}

		uint32_t swap_ipv4 = ipv4->daddr;
		ipv4->daddr = ipv4->saddr;
		ipv4->saddr = swap_ipv4;

	}
	else if (eth_proto == __bpf_htons(ETH_P_IPV6))
	{
		if (!(ipv6 = parse_ipv6hdr(&c))
		||    ipv6->nexthdr  != IPPROTO_UDP
		||   (r = udp_dns_reply_v6(&c, &ipv6->saddr)))
			return r < 0 ? XDP_ABORTED : XDP_PASS;

		struct in6_addr swap_ipv6 = ipv6->daddr;
		ipv6->daddr = ipv6->saddr;
		ipv6->saddr = swap_ipv6;
	}
	else
	{
		return XDP_PASS;
	}

	uint8_t swap_eth[ETH_ALEN];
	memcpy(swap_eth, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, swap_eth, ETH_ALEN);

	// bounce the request
	return XDP_TX;
}

char __license[] SEC("license") = "GPL";
