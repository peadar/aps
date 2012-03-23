#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <limits.h>
#include "pscan.h"

#ifndef LONG_BIT
#define LONG_BIT (CHAR_BIT * sizeof (long))
#endif

#ifndef IPPORT_MAX
#define IPPORT_MAX 65535
#endif

static int havePorts = 0;
static unsigned long servicePorts[IPPORT_MAX / LONG_BIT];

struct PortScanner {
    in_port_t firstPort;
    in_port_t lastPort;
    struct addrinfo *currAddr;
    int currentPort;
    int verbose;
    int numericService;
    int servicesOnly;
    struct con_info **connections;
    struct pollfd *sockets;
    int socketCount;
    int maxSockets;
    struct addrinfo *hostInformation;
    FinishFunc finishFunc;
    void *udata;
};

struct con_info {
    struct addrinfo *ci_ai;
    struct sockaddr *ci_sa;
};

static void cleanup(int fd, struct con_info *);
static void openSocket(struct PortScanner *);
static void nextPort(struct PortScanner *);
static void finish(struct PortScanner *, int fd, struct con_info *, int error);
static void launchConnects(struct PortScanner *);

static int
addrsFor(const char *hostname, struct addrinfo **hi)
{
    int i, j, rc;
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *ai = 0;
    int wild = 0;

    for (i = 0;; i++) {
        switch (hostname[i]) {
        case '\0':
            if (wild != 0)
                return 1;
            if ((rc = getaddrinfo(hostname, 0, &hints, &ai)) != 0) {
                    fprintf(stderr, "cannot resolve address '%s': %s\n",
                                hostname, gai_strerror(rc));
                    return 0;
            }
            while (*hi != 0)
                hi = &(*hi)->ai_next;
            *hi = ai;
            return 1;
            break;
        case '*':
            for (j = 1; j < 254; j++) {
                char buf[NI_MAXHOST];
                snprintf(buf, sizeof buf, "%.*s%d%s", i, hostname, j, hostname + i + 1);
                if (addrsFor(buf, hi) == 0)
                    return 0;
                wild++;
            }
            break;
        }
    }
}

struct PortScanner *
newPortScanner(const char *host,
        in_port_t firstPort,
        in_port_t lastPort,
        int verbose,
        int servicesOnly,
        int maxSockets,
        FinishFunc func,
        void *udata)
{
    struct PortScanner *ps;
    struct servent *ent;

    if (servicesOnly && !havePorts) {
        havePorts = 1;
        for (setservent(1); (ent = getservent()); ) {
            in_port_t port = ntohs(ent->s_port);
            servicePorts[port/LONG_BIT] |= 1 << port % LONG_BIT;
        }
    }

    ps = malloc(sizeof *ps);
        ps->hostInformation = 0;
        if (addrsFor(host, &ps->hostInformation) == 0)
            return 0;
    ps->firstPort = firstPort;
    ps->lastPort = lastPort;
    ps->verbose = verbose;
    ps->servicesOnly = servicesOnly;
    ps->maxSockets = maxSockets;
    ps->sockets = malloc(sizeof ps->sockets[0] * maxSockets);
    ps->connections = malloc(sizeof ps->connections[0] * maxSockets);
    ps->socketCount = 0;
    ps->currAddr = ps->hostInformation;
    ps->currentPort = ps->firstPort;
    ps->finishFunc = func;
    ps->udata = udata;
    return ps;
}

/*
 * Wait for previously launched asynch calls to terminate.
 * Return 0 if there's nothing left to do.
 */
int
pollPortScanner(struct PortScanner *ps)
{
    int i, rc, sockerror;
        socklen_t errlen;
    struct pollfd *pfds = ps->sockets;

    launchConnects(ps);
    if (ps->socketCount == 0)
        return 0;
    rc = poll(ps->sockets, ps->socketCount, -1);
    if (rc == -1) {
        if (errno != EINTR) {
        printf("poll failed: %s\n", strerror(errno));
        return 0;
        } else {
        return 1;
        }
    }
    for (i = ps->socketCount; i--;) {
        if (pfds[i].revents & (POLLOUT|POLLERR)) {
            errlen = sizeof sockerror;
            if (getsockopt(pfds[i].fd, SOL_SOCKET,
                SO_ERROR, &sockerror, &errlen) != 0)
                err(-1, "getsockopt(SO_ERROR)");
            finish(ps, pfds[i].fd, ps->connections[i], sockerror);
            --ps->socketCount;
            pfds[i] = pfds[ps->socketCount];
            ps->connections[i] = ps->connections[ps->socketCount];
            rc--;
        }
    }
    return 1;
}

/*
 * clean up a port scanner instance.
 */
void
deletePortScanner(struct PortScanner *ps)
{
    int i;
    for (i = 0; i < ps->socketCount; i++)
        cleanup(ps->sockets[i].fd, ps->connections[i]);
    freeaddrinfo(ps->hostInformation);
    free(ps->sockets);
    free(ps->connections);
}

static void
nextAddress(struct PortScanner *ps)
{
    ps->currAddr = ps->currAddr->ai_next;
    if (ps->currAddr)
        ps->currentPort = ps->firstPort - 1;
}

static void
nextPort(struct PortScanner *ps)
{
    do {
        ps->currentPort++;
    } while (ps->servicesOnly && (servicePorts[ps->currentPort / LONG_BIT]
        & 1 << ps->currentPort % LONG_BIT) == 0);
    if (ps->currentPort > ps->lastPort)
        nextAddress(ps);
}

static void
finish(struct PortScanner *ps, int fd, struct con_info *ci, int error)
{
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    char numericService[NI_MAXSERV];
    struct protoent *pent;
    int rc;

    pent = getprotobynumber(ci->ci_ai->ai_protocol);
    rc = getnameinfo(ci->ci_sa, ci->ci_ai->ai_addrlen, host,
        sizeof host, service, sizeof service, NI_NUMERICHOST);
    rc += getnameinfo(ci->ci_sa, ci->ci_ai->ai_addrlen, 0, 0,
        numericService, sizeof numericService, NI_NUMERICSERV);
    if (rc == 0) {
        ps->finishFunc(ps->udata, host, numericService,
            service, pent->p_name, error);
    } else {
        errx(-1, "cannot get service details: %s",
            gai_strerror(rc));
    }
    cleanup(fd, ci);
}

static void
cleanup(int fd, struct con_info *ci)
{
    if (fd != -1)
        close(fd);
    free(ci->ci_sa);
    free(ci);
}

static void
openSocket(struct PortScanner *ps)
{
    int fdflags, fd;
    struct con_info *ci;
    in_port_t netPort;

    ci = malloc(sizeof *ci);
    ci->ci_sa = malloc(ps->currAddr->ai_addrlen);
    ci->ci_ai = ps->currAddr;
    memcpy(ci->ci_sa, ps->currAddr->ai_addr, ps->currAddr->ai_addrlen);

    netPort = htons(ps->currentPort);
    switch (ps->currAddr->ai_family) {
    case PF_INET6:
        ((struct sockaddr_in6 *)ci->ci_sa)->sin6_port = netPort;
        break;

    case PF_INET:
        ((struct sockaddr_in *)ci->ci_sa)->sin_port = netPort;
        break;

    default:
        fprintf(stderr, "unsupported address family %d\n",
            ps->currAddr->ai_family);
        cleanup(-1, ci);
        nextAddress(ps);
        return;
    }

    fd = socket(ps->currAddr->ai_family, ps->currAddr->ai_socktype,
        ps->currAddr->ai_protocol);

    if (fd == -1) {
        /*
         * Our kernel may not be able to connect on the specified
         * address format. Don't be too harsh.
         */
        if (errno == EPROTONOSUPPORT) {
            if (ps->verbose)
                fprintf(stderr,
                    "(no support for address family="
                    "%d, type=%d, proto=%d)\n",
                    ps->currAddr->ai_family,
                    ps->currAddr->ai_socktype,
                    ps->currAddr->ai_protocol);
            cleanup(-1, ci);
            ps->currAddr = ps->currAddr->ai_next;
            return;
        } else {
            err(-1, "socket");
        }
    }

    /* Mark socket non-blocking */
    if ((fdflags = fcntl( fd, F_GETFL, 0)) == -1)
        err(-1, "fcntl(F_GETFL)");
    if (fcntl(fd, F_SETFL, fdflags | O_NONBLOCK) == -1)
        err(-1, "fcntl(F_GETFL)");

    /* Attempt connect */
    if (connect(fd, ci->ci_sa, ps->currAddr->ai_addrlen) == 0) {
        /* immediate success */
        finish(ps, fd, ci, 0);
    } else {
        switch (errno) {
        case EINPROGRESS:
        case EAGAIN:
            /* Operation in progress. (add to polling set) */
            ps->sockets[ps->socketCount].fd = fd;
            ps->sockets[ps->socketCount].events = POLLOUT;
            ps->connections[ps->socketCount] = ci;
            ps->socketCount++;
            break;
        default:
            /* Immediate error */
            finish(ps, fd, ci, errno);
            break;
        }
    }

    /* Move on to next port */
    nextPort(ps);
}

/* Do as many asynch connect calls as we are allowed. */
static void
launchConnects(struct PortScanner *ps)
{
    while (ps->socketCount < ps->maxSockets && ps->currAddr)
        openSocket(ps);
}

