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
#include <sys/socket.h>
#include <sys/types.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <net/if.h>

int main(int argc, char **argv)
{
	int fd;
	struct sockaddr_ll lla = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(0x0800),
		.sll_ifindex = if_nametoindex("eth0")
	};
	
	unsigned char r_ip_header[20];
	unsigned char r_udp_header[8];
	uint16_t r_frame_no;
	uint16_t r_chunk_no;
	unsigned char r_frame_data[4096];

	unsigned char *frame_buffer;
	size_t frame_buffer_size = 4 * 1024 * 1024;
	frame_buffer = malloc(frame_buffer_size);
	if (!frame_buffer) {
		fprintf(stderr, "Memory allocation failure\n");
		return 1;
	}

	size_t frame_size = 0;
	int current_frame = -1;
	int current_chunk = -1;
	int frame_missed = 0;

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
		{
			.iov_base = &r_frame_data,
			.iov_len = sizeof(r_frame_data)
		}
	};

	struct msghdr msg = {
		.msg_iov = iovs,
		.msg_iovlen = sizeof(iovs) / sizeof(iovs[0])
	};
	ssize_t received;

	fd = socket(AF_PACKET, SOCK_DGRAM, htons(0x0800));
	if (fd < 0) {
		perror("Error creating socket");
		return 1;
	}

	int socket_buf = 10000000;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &socket_buf, sizeof(socket_buf))) {
		perror("Error configuring socket buffer");
		return 1;
	}

	if (!lla.sll_ifindex) {
		fprintf(stderr, "Couldn't find 'eth0'. Abort.\n");
		return 1;
	}

	if (bind(fd, (struct sockaddr*)&lla, sizeof(lla))) {
		perror("Error binding socket");
		return 1;
	}

	while (1) {
		received = recvmsg(fd, &msg, 0);
		if (received < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				perror("Retrying because of");
				continue;
			}
			perror("Error receiving from socket");
			return 1;
		}
		if (received == 0) {
			fprintf(stderr, "Socket closed.\n");
			return 1;
		}
		
		if (received < 20 + 8 + 4) { /* IP + UDP + Counters */
			fprintf(stderr, "Received packet too short, skip.\n");
			continue;
		}

		uint8_t ip_version = (r_ip_header[0] & 0xf0) >> 4;
		uint8_t ip_ihl = 4 * (r_ip_header[0] & 0x0f);

		if (ip_version != 4) {
			fprintf(stderr, "Received packet is not IPv4. Skip.\n");
			continue;
		}

		if (ip_ihl != 20) {
			fprintf(stderr, "Received IP header is not 20byte. Skip.\n");
			continue;
		}

		uint8_t ip_protocol = r_ip_header[9];
		if (ip_protocol != 17) {
			fprintf(stderr, "Received packet is not UDP. Skip.\n");
			continue;
		}

		uint16_t udp_src_port, udp_dst_port, udp_len;
		memcpy(&udp_src_port, &r_udp_header[0], 2);
		memcpy(&udp_dst_port, &r_udp_header[2], 2);
		memcpy(&udp_len, &r_udp_header[4], 2);
	
		udp_src_port = ntohs(udp_src_port);
		udp_dst_port = ntohs(udp_dst_port);
		udp_len = ntohs(udp_len);

		if (udp_src_port != 2068 || udp_dst_port != 2068) {
			if (udp_src_port == 2067 && udp_dst_port == 2067)
				continue;
			fprintf(stderr, "Data not on expected UDP port. "
				"(src==%d,dst==%d)\n", udp_src_port, udp_dst_port);
			continue;
		}

		if (received < 20 + 8 + udp_len) {
			fprintf(stderr,
				"Received data len doesn't match announced len\n");
			continue;
		}

		uint16_t data_len = udp_len - 4;
		uint16_t frame_no = ntohs(r_frame_no);
		uint16_t chunk_no = ntohs(r_chunk_no) & ~0x8000;
		bool last_chunk = ntohs(r_chunk_no) & 0x8000;

		if (frame_no != current_frame) {
			frame_size = 0;
			if (chunk_no != 0) {
				fprintf(stderr,
					"Received new frame, but missed chunk 0\n");
				current_frame = -1;
			} else {
				fprintf(stderr, "Starting new frame %d\n", frame_no);
				current_frame = frame_no;
				current_chunk = 0;
				frame_missed = 0;
			}
		}

		if (frame_no == current_frame && chunk_no == current_chunk) {
			if (data_len <= frame_buffer_size - frame_size) {
				memcpy(frame_buffer + frame_size,
					r_frame_data,
					data_len);
				frame_size += data_len;
			} else {
				if (!frame_missed) {
					fprintf(stderr, "Buffer too short.\n");
				}
				frame_missed = 1;
			}
			current_chunk += 1;
		} else if (frame_no == current_frame) {
			if (!frame_missed) {
				fprintf(stderr, "Missed a chunk for a frame. (Got chunk %d"
					" but expected %d)\n", chunk_no, current_chunk);
			}
			frame_missed = 1;
		}

		if (last_chunk && frame_size != 0 && !frame_missed) {
			char path[512];
			FILE *frame;

			fprintf(stderr, "Saving frame %d.\n", current_frame);
			snprintf(path, 512,
				"frame-%010d.jpg", current_frame);
			frame = fopen(path, "wb");
			if (frame) {
				fwrite(frame_buffer, frame_size, 1,
						frame);
				fclose(frame);
			}
		}
	}

	return 0;
}
