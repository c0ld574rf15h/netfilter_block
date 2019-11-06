#include <stdio.h>
#include <stdlib.h>
#include <string.h>					/* for memcmp */
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define HOST_NAME_SZ	50
#define NUM_METHODS		6
#define TRUE			1
#define FALSE			0

const char* http_methods[NUM_METHODS] = {
		"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"
};
char filter_host[HOST_NAME_SZ];
int filter_flag = FALSE;

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%c", buf[i]);
	}
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("[*] id : %u\n", id);
		//printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);
		/*
		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);*/
	}

	mark = nfq_get_nfmark(tb);
	/*if (mark)
		printf("mark=%u ", mark);*/

	ifi = nfq_get_indev(tb);
	/*
	if (ifi)
		printf("indev=%u ", ifi);*f

	ifi = nfq_get_outdev(tb);
	/*if (ifi)
		printf("outdev=%u ", ifi);*/
	ifi = nfq_get_physindev(tb);
	/*if (ifi)
		printf("physindev=%u ", ifi);*/

	ifi = nfq_get_physoutdev(tb);
	/*if (ifi)
		printf("physoutdev=%u ", ifi);*/

	ret = nfq_get_payload(tb, &data);
	/*if (ret >= 0)
		printf("payload_len=%d ", ret);*/

	//fputc('\n', stdout);

	// Extracting information from the packet
	int ip_len = (data[0] & 0x0F) << 2;
	int tcp_len = (data[ip_len + 12] & 0xF0) >> 2;
	int app_offset = ip_len + tcp_len;
	printf("[*] Application Layer Offset : %d\n", app_offset);

	int require_chk = FALSE;

	// Check whether the user is sending a HTTP request
	for(int i=0;i<NUM_METHODS;++i) {
		if(!memcmp(data+app_offset, http_methods[i], strlen(http_methods[i]))) {
			dump(data+app_offset, 64);
			require_chk = TRUE;
			break;
		}
	}

	// Check whether the host field matches our condition
	if(require_chk == TRUE) {
		int idx = 0;
		while(TRUE) {
			if(!memcmp(data+app_offset+idx, "Host: ", 6)) {
				puts("Found Host:");
				if(!memcmp(data+app_offset+idx+6, filter_host, strlen(filter_host))) {
					filter_flag = TRUE;
					break;
				} else {
					filter_flag = FALSE;
					break;
				}
			}
			idx += 1;
		}
	}
	
	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	filter_flag = FALSE;
	u_int32_t id = print_pkt(nfa);

	if(filter_flag == TRUE) return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	else if(filter_flag == FALSE) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	else {	// What the hell have you done wrong...?
		fputs("[!] INVALID FILTER_FLAG VALUE", stderr);
		return -1;
	}
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if(argc != 2) {
		fputs("[!] REQUIRES DOMAIN NAME AS FIRST ARGUMENT", stderr);
		return -1;
	}
	strncpy(filter_host, argv[1], strlen(argv[1]));
	printf("Filter host : %s\nLength:%d", filter_host, strlen(argv[1]));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
