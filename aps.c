/*
 * aps: A Port Scanner
 * Copyright (c) Peter Edwards, October 2003
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Port scanner that will work with IP and IPv6.
 * The code is almost address-family neutral, but because it scans ports, it
 * needs to know what a port number is. Further network types can be
 * supported by augmenting the address manipulation done in openSocket().
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include "pscan.h"

static int verbose = 0;
static const char *progName;

static void
usage()
{
	fprintf(stderr, "usage: %s "
	    "[-f <first port>] "
	    "[-l <last port>] "
	    "[-m <max open sockets>] "
	    "[-s] "
	    "[-v] "
	    "<host>\n", progName);
	exit(-1);
}

static int
intOption(int min, int max)
{
	int rc;
	char *p = optarg;
	rc = strtol(p, &p, 10);
	if (!p || p[0] != '\0' || rc < min || rc > max) {
		usage();
	}
	return rc;
}

static void
humanReadable(void *udata,
	    const char *host,
	    const char *service,
	    const char *numericService,
	    const char *protocol, int error)
{
	if (error == 0)
		printf("host=%s, port=%s(%s), proto=%s\n",
		    host, numericService, service, protocol);
        else if (verbose) {
            const char *p = strerror(error);
            fprintf(stderr, "ERR: %s: host=%s, port=%s(%s), proto=%s\n",
                    p ? p : "unknown", host, numericService, service, protocol);
        }
}

int
main(int argc, char *argv[])
{
	int c;
	int firstPort = 1;
	int lastPort = 65535;
	int servicesOnly = 0;
	int maxSockets = 30;
	struct PortScanner *ps;

	progName = basename(argv[0]);
	while ((c = getopt(argc, argv, "f:l:m:sv")) != -1) {
		switch (c) {
		case 'v':
			verbose++; break;
			break;
		case 'f':
			firstPort = intOption(1, 65535);
			break;
		case 'l':
			lastPort = intOption(1, 65535);
			break;
		case 's':
			servicesOnly = 1;
			break;
		case 'm':
			maxSockets = intOption(1, 10000);
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage();
	ps = newPortScanner(
			argv[0],
			firstPort,
			lastPort,
			verbose,
			servicesOnly,
			maxSockets,
			humanReadable,
			0);
	if (ps) {
	    while (pollPortScanner(ps))
		    ;
	    deletePortScanner(ps);
	}
	return 0;
}
