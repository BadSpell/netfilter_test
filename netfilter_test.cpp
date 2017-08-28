#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <ctype.h>
#include <stdint.h>
#include <set>
#include <fstream>
#include <iostream>
#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;
typedef struct _IP_HEADER
{
	uint8_t version; //0x0E
	uint8_t dscp; //0x0F
	uint16_t totalLength; //0x10
	uint16_t id; //0x12
	uint16_t flag; //0x14
	uint8_t ttl; //0x16
	uint8_t protocol; //0x17
	uint16_t headerchecksum; //0x18
	uint32_t sourceip; //0x1A
	uint32_t destip; //0x1E
}  __attribute__((packed)) IP_HEADER, *LPIP_HEADER;

typedef struct _TCP_HEADER
{
	uint16_t sourceport; //0x22
	uint16_t destport; //0x24
	uint32_t seqnum;
	uint32_t acknum;
	uint8_t headerlen;
	uint8_t flag;
	uint16_t wnd;
	uint16_t checksum;
	uint16_t urgptr;
} __attribute__((packed)) TCP_HEADER, *LPTCP_HEADER;

set<string> table;

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
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	const u_char *packet;
	LPIP_HEADER ipHeader;
	LPTCP_HEADER tcpHeader;
	char *tcpdata;
	char *copydata;
	int szTcpdata;

	if(nfq_get_payload(nfa, (unsigned char **)&packet) == -1)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	ipHeader = (LPIP_HEADER)packet;
	if (ipHeader->protocol != IPPROTO_TCP) // Check if TCP
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	tcpHeader = (LPTCP_HEADER)(packet + sizeof(IP_HEADER));
	if (ntohs(tcpHeader->sourceport) != 80 && ntohs(tcpHeader->destport) != 80) // Only HTTP port
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	
	tcpdata = (char *)(packet + sizeof(IP_HEADER) + (tcpHeader->headerlen >> 4) * 4);
	szTcpdata = ntohs(ipHeader->totalLength) - sizeof(IP_HEADER) - (tcpHeader->headerlen >> 4) * 4;
	copydata = new char[szTcpdata + 1];
	memcpy(copydata, tcpdata, szTcpdata);
	copydata[szTcpdata] = '\0';

	char *hostStr = "Host: ";
	char *s = strstr(copydata, hostStr);
	if (s)
	{
		int i;
		s += strlen(hostStr);
		for (i = 0; s[i] != '\r' && s[i] != '\0'; i++);
		s[i] = '\0';
		
		string str = s;
		set<string>::iterator iter;
		iter = table.find(str);
		if (iter != table.end())
		{
			printf("Blocked Website: [%s]\n", s);

			delete []copydata;
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}
	}
	
	delete []copydata;
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	string inputString;

	ifstream inFile("filter_list.txt");
	while (!inFile.eof())
	{
		getline(inFile, inputString);
		int first = inputString.find("http://");
		if (first == -1)
			 first = inputString.find("https://") + 1;

		int last = inputString.substr(first + 7).find("/");
		string hostName = inputString.substr(first + 7, last);
		table.insert(hostName);
		cout << "Add BlockList: " << hostName << endl;
	}
	inFile.close();

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
		 * on your application, this error may be ignored. Please, see
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
