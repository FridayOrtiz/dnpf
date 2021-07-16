#define KBUILD_MODNAME "timebase"
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")
#include <linux/kconfig.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/pkt_cls.h>

#define IPPROTO_UDP 17
#define VALUE_LEN 8

static unsigned long long (*bpf_get_smp_processor_id)(void) =
    (void *)8;
static int (*bpf_perf_event_output)(void *ctx, void *map, unsigned long long flags, void *data, int size) =
    (void *)25;
static int (*bpf_skb_store_bytes)(struct __sk_buff *skb, u32 offset, const void *from, u32 len, u64 flags) =
    (void *)9;
static int (*bpf_skb_change_tail)(struct __sk_buff *skb, u32 len, u64 flags) =
    (void *)38;
//static int (*bpf_skb_load_bytes)(struct __sk_buff *skb, u32 offset, const void *to, u32 len) =
//    (void *)26;

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
    unsigned int id;
    unsigned int pinning;
};

struct bpf_map_def dns_filter_events __attribute__((section("maps/dns_filter_events"), used))  = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(u32),
        .max_entries = 1024,
        .map_flags = 0,
        .id = 0,
        .pinning = 0,
};

/*
 * 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      ID                       |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    QDCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ANCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    NSCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ARCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

struct dns_header {
    u16 id;
    u16 codes;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
};

/*
 * 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                               |
 * /                                               /
 * /                      NAME                     /
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      TYPE                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     CLASS                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      TTL                      |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                   RDLENGTH                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 * /                     RDATA                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

struct __attribute__((__packed__)) cv_resource_record {
    char name[2];
    u16 type;
    u16 class;
    u16 pad;
    u16 ttl;
    u16 rdlength;
    char payload[4];
    u32 fcs;
};

/*
 * +------------+--------------+------------------------------+
 * | Field Name | Field Type   | Description                  |
 * +------------+--------------+------------------------------+
 * | NAME       | domain name  | MUST be 0 (root domain)      |
 * | TYPE       | u_int16_t    | OPT (41)                     |
 * | CLASS      | u_int16_t    | requestor's UDP payload size |
 * | TTL        | u_int32_t    | extended RCODE and flags     |
 * | RDLEN      | u_int16_t    | length of all RDATA          |
 * | RDATA      | octet stream | {attribute,value} pairs      |
 * +------------+--------------+------------------------------+
 */
struct opt_record {
	char name;
	u16 type;
	u16 class;
	u32 ttl;
	u16 rdlen;
	char cookie[28]; // we're assuming we're copying the cookie at the end
};

struct dns_filter_event {
    u32 retcode;
};

__attribute__((section("classifier/dns_firewall"), used)) int dns_firewall(struct __sk_buff *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void*)eth + sizeof(*eth) > data_end)
		return TC_ACT_OK;
	struct iphdr *ip = data + sizeof(*eth);
	if ((void*)ip + sizeof(*ip) > data_end)
		return TC_ACT_OK;

	if (ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;
	struct udphdr *udp = (void *)ip + sizeof(*ip);
	if ((void*) udp + sizeof(*udp) > data_end)
		return TC_ACT_OK;


	if (udp->dest == ntohs(53)) {
		struct dns_filter_event ev = {
			.retcode = 0,
		};

		bpf_perf_event_output(ctx,
		                      &dns_filter_events,
		                      bpf_get_smp_processor_id(),
		                      &ev,
		                      sizeof(ev));

		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

char _license[] __attribute__((section("license"), used)) = "Dual MIT/GPL";
uint32_t _version __attribute__((section("version"), used)) = 0xFFFFFFFE;
