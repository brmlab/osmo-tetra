/* Test program for tetra burst synchronizer */

/* (C) 2011 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/stat.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>

#include "tetra_common.h"
#include <phy/tetra_burst.h>
#include <phy/tetra_burst_sync.h>
#include "tetra_gsmtap.h"

void *tetra_tall_ctx;
char *dumpdir;

char *pcap_file_path;
int arfcn;
int ssi;
int tsn;

int main(int argc, char **argv)
{
	int fd;
	int opt;

	struct tetra_rx_state *trs;
	struct tetra_mac_state *tms;

	char no_udp_tap = 0;

	while ((opt = getopt(argc, argv, "a:t:d:n")) != -1) {
		switch (opt) {
		case 'a':
			arfcn = atoi(optarg);
			break;
		case 't':
			//pcap_file_path = malloc(strlen(optarg));
			//memcpy(pcap_file_path, optarg, strlen(optarg));
			pcap_file_path = optarg;
			break;
		case 'd':
			dumpdir = optarg;
			break;
		case 'n':
			fprintf(stderr, "-n does not work\n");
			exit(1);
			no_udp_tap = 1;
			break;
		default:
			fprintf(stderr, "Unknown option %c\n", opt);
			exit(2);
		}
	}

	if (argc <= optind) {
		fprintf(stderr, "Usage: %s [-a ARFCN] [-t GSMTAP_PATH] [-d DUMPDIR] [-n] -s [-v] <filestream>\n", argv[0]);
		fprintf(stderr, "Usage: -n .. no UDP GSMTAP messages\n");
		fprintf(stderr, "Usage: %s <file_with_1_byte_per_bit>\n", argv[0]);
		exit(1);
	}

	if (no_udp_tap == 0) {
		tetra_gsmtap_init("localhost", 0);
	}

	tms = talloc_zero(tetra_tall_ctx, struct tetra_mac_state);
	tetra_mac_state_init(tms);

	trs = talloc_zero(tetra_tall_ctx, struct tetra_rx_state);
	trs->burst_cb_priv = tms;

	fd = open(argv[optind], O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(2);
	}

	while (1) {
		uint8_t buf[64];
		int len;

		len = read(fd, buf, sizeof(buf));
		if (len < 0) {
			perror("read");
			exit(1);
		} else if (len == 0) {
			printf("EOF");
			break;
		}
		tetra_burst_sync_in(trs, buf, len);
	}

	talloc_free(trs);
	talloc_free(tms);

	exit(0);
}
