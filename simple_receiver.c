#define _GNU_SOURCE 1

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <byteswap.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <net/if.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#define DEBUG 1
#define FRAMES_PER_SECOND 25
#define FRAME_BUFFER_SIZE (2 * 1024 * 1024)
#define TX_BUFFER_LEN 2048

#ifdef DEBUG
#define dbg_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbg_printf(...)
#endif

struct lk_receiver;

struct lk_client {
	struct lk_receiver *lkr;
	struct event_base *event_base;
	int fd;
	struct bufferevent *buffer;

	struct lk_client *next;
};

struct lk_receiver {
	struct event_base *event_base;

	unsigned char *buffer[3];
	size_t buffer_len[3];
	int buffer_locked;

	int fd;
	struct event *event_in;

	uint16_t current_frame;
	uint16_t current_chunk;
	bool frame_missed;

	struct event *tx_timer;
	char tx_buffer[TX_BUFFER_LEN];
	unsigned idle_timer;

	int sfd;
	struct event *server_event;
	struct lk_client *clients;
};

static int lk_receiver_load_fallback(struct lk_receiver *lkr)
{
	FILE *fallback;

	fallback = fopen("fallback.jpg", "r");
	if (!fallback) {
		perror("Couldn't open fallback.jpg");
		return 1;
	}

	lkr->buffer_len[2] = 0;

	while (!feof(fallback)) {
		size_t bytes_read;
		
		bytes_read = fread(lkr->buffer[2] + lkr->buffer_len[2], 1, 4096,
				fallback);
		if (ferror(fallback) != 0) {
			perror("Couldn't read fallback.jpg");
			return 1;
		}

		lkr->buffer_len[2] += bytes_read;
	}

	fclose(fallback);
	dbg_printf("Fallback image loaded, %zu bytes.\n", lkr->buffer_len[2]);
	return 0;
}

static size_t *lkr_target_buf_len(struct lk_receiver *lkr)
{
	if (lkr->buffer_locked == 1) {
		return &lkr->buffer_len[0];
	} else {
		return &lkr->buffer_len[1];
	}
}

static unsigned char *lkr_target_buf(struct lk_receiver *lkr)
{
	if (lkr->buffer_locked == 1) {
		return lkr->buffer[0];
	} else {
		return lkr->buffer[1];
	}
}

static void lkr_swap_buf(struct lk_receiver *lkr)
{
	lkr->buffer_locked = 1 - lkr->buffer_locked;
	lkr->idle_timer = 0;
}

static void lkr_handle_chunk(struct lk_receiver *lkr, uint16_t frame_no,
			     uint16_t chunk_no, bool last_chunk,
			     unsigned char *frame_data, size_t frame_len)
{
	if (frame_no != lkr->current_frame) {
		*lkr_target_buf_len(lkr) = 0;
		if (chunk_no != 0) {
			lkr->current_frame = -1;
		} else {
			lkr->current_frame = frame_no;
			lkr->current_chunk = 0;
			lkr->frame_missed = false;
		}
	}

	if (frame_no == lkr->current_frame && chunk_no == lkr->current_chunk) {
		if (frame_len <= FRAME_BUFFER_SIZE - *lkr_target_buf_len(lkr)) {
			memcpy(lkr_target_buf(lkr) + *lkr_target_buf_len(lkr),
			       frame_data, frame_len);
			*lkr_target_buf_len(lkr) += frame_len;
		} else {
			if (!lkr->frame_missed) {
				fprintf(stderr, "Buffer overflow.\n");
			}
			lkr->frame_missed = true;
		}
		lkr->current_chunk += 1;
	} else if (frame_no == lkr->current_frame) {
		lkr->frame_missed = true;
	}

	if (last_chunk && *lkr_target_buf_len(lkr) != 0 && !lkr->frame_missed) {
		lkr_swap_buf(lkr);
	}
}

static void lkr_recv(evutil_socket_t fd, short event, void *userdata)
{
	struct lk_receiver *lkr = userdata;

	unsigned char r_ip_header[20];
	unsigned char r_udp_header[8];
	uint16_t r_frame_no;
	uint16_t r_chunk_no;
	unsigned char r_frame_data[4096];
	ssize_t received;

	struct iovec iovs[] = {
		{
			.iov_base = &r_ip_header,
			.iov_len = sizeof(r_ip_header)
		},
		{
			.iov_base = &r_udp_header,
			.iov_len = sizeof(r_udp_header)
		},
		{
			.iov_base = &r_frame_no,
			.iov_len = sizeof(r_frame_no)
		},
		{
			.iov_base = &r_chunk_no,
			.iov_len = sizeof(r_chunk_no)
		},
		{	.iov_base = &r_frame_data,
			.iov_len = sizeof(r_frame_data)
		}
	};

	struct msghdr msg = {
		.msg_iov = iovs,
		.msg_iovlen = sizeof(iovs) / sizeof(iovs[0])
	};

	received = recvmsg(fd, &msg, 0);
	if (received < 0) {
		if (errno == EINTR || errno == EAGAIN)
			return;
		perror("Error receiving from socket");
		if (event_base_loopbreak(lkr->event_base))
			abort();
	}

	if (received == 0) {
		fprintf(stderr, "Connection closed.\n");
		if (event_base_loopbreak(lkr->event_base))
			abort();
	}

	if (received < 20 + 8 + 4) { /* IP + UDP + Counter */
		dbg_printf("Received packet too short, skip.\n");
		return;
	}

	uint8_t ip_version = (r_ip_header[0] & 0xf0) >> 4;
	uint8_t ip_ihl = 4 * (r_ip_header[0] & 0x0f);

	if (ip_version != 4) {
		/* dbg_printf("Received packet is not IPv4.\n"); */
		return;
	}

	if (ip_ihl != 20) {
		/* dbg_printf("Received IP header is not 20 byte. Skip.\n"); */
		return;
	}

	uint8_t ip_protocol = r_ip_header[9];

	if (ip_protocol != 17) {
		/* dbg_printf("Received packet is not UDP. Skip.\n"); */
		return;
	}

	uint16_t udp_src_port, udp_dst_port, udp_len;

	memcpy(&udp_src_port, &r_udp_header[0], 2);
	memcpy(&udp_dst_port, &r_udp_header[2], 2);
	memcpy(&udp_len, &r_udp_header[4], 2);

	udp_src_port = ntohs(udp_src_port);
	udp_dst_port = ntohs(udp_dst_port);
	udp_len = ntohs(udp_len);

	if (udp_src_port != 2068 || udp_dst_port != 2068)
		return;

	if (received < 20 + 8 + udp_len) {
		fprintf(stderr, "Received data len doesn't match len in header\n");
		return;
	}

	uint16_t frame_no = ntohs(r_frame_no);
	uint16_t chunk_no = ntohs(r_chunk_no) & ~0x8000;
	bool last_chunk = ntohs(r_chunk_no) & 0x8000;

	lkr_handle_chunk(lkr, frame_no, chunk_no, last_chunk,
			 r_frame_data, udp_len - 4);
}

static int lk_receiver_create_socket(struct lk_receiver *lkr)
{
	struct sockaddr_ll lla = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(0x800)
	};

	lkr->fd = socket(AF_PACKET, SOCK_DGRAM, htons(0x8000));
	if (lkr->fd < 0) {
		perror("Error creating socket");
		return 1;
	}

	/* socket buffer? */

	lla.sll_ifindex = if_nametoindex("eth0");
	if (!lla.sll_ifindex) {
		fprintf(stderr, "Couldn't find 'eth0'.\n");
		return 1;
	}

	if (bind(lkr->fd, (struct sockaddr*)&lla, sizeof(lla))) {
		perror("Error binding socket");
		return 1;
	}

	lkr->event_in = event_new(lkr->event_base, lkr->fd, EV_READ | EV_PERSIST,
					lkr_recv, lkr);
	if (!lkr->event_in || event_add(lkr->event_in, NULL)) {
		fprintf(stderr, "Couldn't create/schedule recv event.\n");
		return 1;
	}

	return 0;
}

static void lkr_send_img(struct lk_receiver *lkr, 
		         unsigned char *buffer, size_t buffer_len)
{
	int written;

	written = snprintf(lkr->tx_buffer, TX_BUFFER_LEN,
			"\r\n--newframe\r\n"
			"Content-Type: image/jpeg\r\n"
			"Content-Length: %zu\r\n\r\n",
			buffer_len);

	if (written < 0) {
		perror("Couldn't print to buffer, abort");
		exit(1);
	}

	for (struct lk_client *lkc = lkr->clients; lkc; lkc = lkc->next) {
		bufferevent_write(lkc->buffer, lkr->tx_buffer, written);
		bufferevent_write(lkc->buffer, buffer, buffer_len);
	}
}

static void lkr_send(evutil_socket_t fd, short what, void *userdata)
{
	struct lk_receiver *lkr = userdata;

	if (lkr->idle_timer < 50)
		lkr->idle_timer++;

	if (lkr->idle_timer >= 50) {
		lkr_send_img(lkr, lkr->buffer[2], lkr->buffer_len[2]);
	} else if (lkr->buffer_locked == 0) {
		lkr_send_img(lkr, lkr->buffer[0], lkr->buffer_len[0]);
	} else {
		lkr_send_img(lkr, lkr->buffer[1], lkr->buffer_len[1]);
	}
}

static int lk_receiver_create_tx(struct lk_receiver *lkr)
{
	struct timeval frame_interval = {
		.tv_sec = 0,
		.tv_usec = 1000000UL / FRAMES_PER_SECOND
	};

	lkr->idle_timer = 50;

	lkr->tx_timer = event_new(lkr->event_base, -1, EV_PERSIST, lkr_send, lkr);
	if (!lkr->tx_timer || event_add(lkr->tx_timer, &frame_interval)) {
		fprintf(stderr, "Couldn't init/register frame tx timer.\n");
		return 1;
	}

	return 0;
}

static void lkc_event(struct bufferevent *event, short what, void *userdata)
{
	struct lk_client *lkc = userdata;

	struct lk_client **i;

	fprintf(stderr, "Client disconnected\n");

	for (i = &lkc->lkr->clients; *i != NULL; i = &(*i)->next) {
		if (*i == lkc) {
			fprintf(stderr, "Client unlinked :)\n");
			*i = lkc->next;
			break;
		}
	}

	bufferevent_free(lkc->buffer);
	close(lkc->fd);
	free(lkc);
}

static void lkr_accept(evutil_socket_t fd, short what, void *userdata)
{
	struct lk_receiver *lkr = userdata;
	struct lk_client *lkc;

	int client_fd;
	
	client_fd = accept(fd, NULL, NULL);
	if (client_fd < 0) {
		perror("Couldn't accept client!");
		return;
	}
	
	fprintf(stderr, "Client connected\n");

	lkc = calloc(1, sizeof(*lkc));
	lkc->lkr = lkr;
	lkc->event_base = lkr->event_base;
	lkc->fd = client_fd;
	lkc->buffer = bufferevent_socket_new(lkr->event_base, lkc->fd, 0);
	if (!lkc->buffer) {
		perror("Couldn't create bufferevent!");
		close(lkc->fd);
		free(lkc);
		return;
	}
	
	bufferevent_setcb(lkc->buffer, NULL, NULL, lkc_event, lkc);

	if (bufferevent_enable(lkc->buffer, EV_WRITE)) {
		perror("Couldn't enable bufferevent!");
		bufferevent_free(lkc->buffer);
		close(lkc->fd);
		free(lkc);
		return;
	}

	lkc->next = lkr->clients;
	lkr->clients = lkc;
}

static int lk_receiver_create_server(struct lk_receiver *lkr)
{
	struct sockaddr_in sai = {
		.sin_family = AF_INET,
		.sin_port = htons(3001),
	};
	sai.sin_addr.s_addr = INADDR_ANY;

	int on = 1;

	lkr->sfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lkr->sfd < 0) {
		perror("Couldn't create server socket");
		return 1;
	}

	if (setsockopt(lkr->sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
		perror("Couldn't set SO_REUSEADDR");
		return 1;
	}

	if (bind(lkr->sfd, (struct sockaddr*)&sai, sizeof(sai))) {
		perror("Couldn't bind server");
		return 1;
	}

	if (listen(lkr->sfd, 5)) {
		perror("Couldn't listen");
		return 1;
	}

	lkr->server_event = event_new(lkr->event_base, lkr->sfd, EV_READ |
			EV_PERSIST, lkr_accept, lkr);
	if (!lkr->server_event || event_add(lkr->server_event, NULL)) {
		fprintf(stderr, "Couldn't init/register server accept event.\n");
		return 1;
	}

	return 0;
}

static struct lk_receiver *lk_receiver_new(struct event_base *eb)
{
	struct lk_receiver *lkr;

	lkr = calloc(1, sizeof(*lkr));

	lkr->event_base = eb;

	/* Allocate image buffers.
	 *
	 * We use three buffers, 0 & 1 are used as a double
	 * buffer so there is always a clean frame while a
	 * new one is being received.
	 * 2 is used to store a fallback image */
	for (size_t i = 0; i < 3; i++) {
		lkr->buffer[i] = malloc(FRAME_BUFFER_SIZE);
		if (!lkr->buffer[i]) {
			perror("Couldn't allocate image buffer");
			return NULL;
		}
	}

	if (lk_receiver_load_fallback(lkr)
	    || lk_receiver_create_socket(lkr)
	    || lk_receiver_create_tx(lkr)
	    || lk_receiver_create_server(lkr))
		return NULL;

	return lkr;
}

int main(int argc, char **argv)
{
	struct event_base *eb;
	struct lk_receiver *lkr;

	struct sigaction sa;
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	sigemptyset(&(sa.sa_mask));
	sigaction(SIGPIPE, &sa, 0);

	eb = event_base_new();
	if (!eb) {
		perror("Could not create event base");
		return 1;
	}

	lkr = lk_receiver_new(eb);

	if (!lkr)
		return 1;

	event_base_dispatch(eb);

	return 0;
}
