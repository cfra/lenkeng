#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/*
const unsigned char trigger_msg[] = {
	0x54, 0x46, 0x36, 0x7A, 0x60, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x03, 0x01, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x02, 0x34,
	0xC2
};*/

unsigned char trigger_msg[4096];
size_t trigger_msg_len;

int load_trigger_msg(void) {
	FILE *f;

	f = fopen("trigger_msg.bin", "rb");
	if (!f) {
		perror("Error opening trigger_msg.bin");
		return 1;
	}
	trigger_msg_len = 0;
	while (!feof(f)) {
		size_t bytes_read;
		bytes_read = fread(trigger_msg + trigger_msg_len, 1,
				   sizeof(trigger_msg) - trigger_msg_len, f);
		if (bytes_read < 0) {
			perror("Error reading trigger_msg.bin");
			return 1;
		}
		trigger_msg_len += bytes_read;
	}
	fclose(f);
	return 0;
}

int main(int argc, char **argv) {
	int fd;
	struct sockaddr_in sin_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(48689)
	};

	if (load_trigger_msg())
		return 1;


	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("Could not open UDP socket");
		return 1;
	}
	
	inet_aton("192.168.168.56", &sin_addr.sin_addr);
	if (bind(fd, (struct sockaddr*)&sin_addr, sizeof(sin_addr)) < 0) {
		perror("Could not bind to source IP.");
		return 1;
	}

	inet_aton("192.168.168.55", &sin_addr.sin_addr);

	while (1) {
		ssize_t sent;

		sent = sendto(fd, trigger_msg, trigger_msg_len, 0,
				(struct sockaddr*)&sin_addr, sizeof(sin_addr));
		if (sent < 0) {
			perror("Could not send UDP packet");
			break;
		}

		sleep(3);
	}

	return 1;
}
