#include <stdio.h>
#include <pcap/pcap.h>

/* net structure*/
#include <netinet/in.h>
#include <fcntl.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

#define start_second 1473087552

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

/* consensus_msg */
typedef enum consensus_msg_code_t{
    // leader election
    ACCEPT_REQ=0,
    ACCEPT_ACK=1,
    MISSING_REQ=2,
    MISSING_ACK=3,
    FORCE_EXEC=4,
    FORWARD_REQ=5,
}con_code;

typedef struct consensus_msg_header_t{
    con_code msg_type;
}consensus_msg_header;

typedef int64_t node_id_t;
typedef uint32_t req_id_t;
typedef uint32_t view_id_t;

typedef struct view_stamp_t{
    view_id_t view_id;
    req_id_t req_id;
}view_stamp;

typedef struct accept_ack_t{
    consensus_msg_header header;
    view_stamp msg_vs;
    node_id_t node_id;
}accept_ack;
#define ACCEPT_ACK_SIZE (sizeof(accept_ack))

typedef enum sys_msg_code_t{
    PING_REQ = 0,
    PING_ACK = 1,
    REQUEST_SUBMIT = 2,
    REQUEST_SUBMIT_REPLY = 3,
    REQUEST_CHECK = 4,
    CONSENSUS_MSG = 5,
    CLIENT_SYNC_REQ = 11,
    CLIENT_SYNC_ACK = 12,
    LEADER_ELECTION_MSG = 16,
}sys_msg_code;

typedef enum req_sub_code_t{
    SUB_SUCC = 0,
    NO_LEADER = 1,
    IN_ERROR = 2,
    NO_RECORD = 3,
    ON_GOING = 4,
    FORFEITED = 5,
    FINISHED = 6,
}req_sub_code;

typedef struct sys_msg_header_t{
    sys_msg_code type;
    size_t data_size;
}sys_msg_header;
#define SYS_MSG_HEADER_SIZE (sizeof(sys_msg_header))

long long timestamp_array[200][9];
int count[1000000];

int max = 3;

FILE *fp_log;
FILE *total_log;
static void handle_package(u_char *args, const struct pcap_pkthdr *header, const u_char *pcakage){
	int package_count = 0;
    if (header->len <= 0) {
        return;
    }
    const struct sniff_ip *ip = (struct sniff_ip*)(pcakage + SIZE_ETHERNET);
    const struct sniff_tcp *tcp;
    u_char *payload;
    u_int size_ip, size_tcp;
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        return;
    }
    tcp = (struct sniff_tcp*)(pcakage + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 4) {
        return;
    }
    payload = pcakage + SIZE_ETHERNET + size_ip + size_tcp;
    int len = header->len - SIZE_ETHERNET - size_ip - size_tcp;
    if (len <= SYS_MSG_HEADER_SIZE ) {
		return;	
	}
	package_count = len / (ACCEPT_ACK_SIZE + SYS_MSG_HEADER_SIZE);
	// printf("accept %d ack\n", package_count);
    consensus_msg_header* msg_header = payload + SYS_MSG_HEADER_SIZE;
    int i = 0;
    for (;i < package_count;i++) {
	    if (msg_header->msg_type == ACCEPT_ACK) {
	        accept_ack *ack = payload + SYS_MSG_HEADER_SIZE;
	         // req_id | node_id | time_s | time_us 
	        timestamp_array[ack->msg_vs.req_id % 200][count[ack->msg_vs.req_id]] = 
            (header->ts.tv_sec - start_second)*1000000 + header->ts.tv_usec;
            count[ack->msg_vs.req_id]++;
            if (count[ack->msg_vs.req_id] >= max) {
                count[ack->msg_vs.req_id] = -100;
                fprintf(fp_log, "%d %lld %lld %lld %lld\n", 
                    ack->msg_vs.req_id, timestamp_array[ack->msg_vs.req_id % 200][0],
                    timestamp_array[ack->msg_vs.req_id % 200][1] - timestamp_array[ack->msg_vs.req_id % 200][0],
                    timestamp_array[ack->msg_vs.req_id % 200][2] - timestamp_array[ack->msg_vs.req_id % 200][1],
                    timestamp_array[ack->msg_vs.req_id % 200][3] - timestamp_array[ack->msg_vs.req_id % 200][2]
                    );
                fprintf(total_log, "%d %lld %lld %lld %lld\n", 
                    ack->msg_vs.req_id, timestamp_array[ack->msg_vs.req_id % 200][0],
                    timestamp_array[ack->msg_vs.req_id % 200][1],
                    timestamp_array[ack->msg_vs.req_id % 200][2],
                    timestamp_array[ack->msg_vs.req_id % 200][3],
                    timestamp_array[ack->msg_vs.req_id % 200][4]
                    );
            }
            
	    }
	    payload += ACCEPT_ACK_SIZE + SYS_MSG_HEADER_SIZE;
	}
}

int main(int argc, char **args) {
    memset(timestamp_array, 0, sizeof(long long)*200*9);
    memset(count, 0, sizeof(int) * 1000000);
    const char *_dev = args[1];
    max = atoi(args[2]);
    max = (max / 2) + 1;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char error_buf[1000];
    if (pcap_lookupnet(_dev, &net, &mask, error_buf) == -1) {
        printf("error getting netmask");
        return -1;
    }
    pcap_t *capture_engine = pcap_open_live(_dev, 3000, 1, 0, error_buf);
    if (capture_engine == NULL) {
        printf("error opening capture engine");
        return -1;
    }
    const char *filter = "dst port 8000 and dst 10.22.1.1";
    struct bpf_program fp;
    if (pcap_compile(capture_engine, &fp, filter, 0, net) == -1) {
        printf("error compiling filter");
        return -1;
    }
    if (pcap_setfilter(capture_engine, &fp) == -1) {
        printf("error setting filter");
        return -1;
    }
    printf("open engine in dev %s\n", _dev);
    fp_log = fopen("/home/jianyu/ack.log", "w+");
    total_log = fopen("/home/jianyu/ack.total.log", "w+");
    if (fp_log == NULL || total_log == NULL) {
        printf("error opening ack log file");
        return -1;
    }
    pcap_loop(capture_engine, -1, handle_package, NULL);
}
