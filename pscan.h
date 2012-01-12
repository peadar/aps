#ifdef __linux__
#include <stdint.h>
typedef uint16_t in_port_t;
#endif

typedef void (*FinishFunc)(void *udata,
			    const char *address,
			    const char *service,
			    const char *serviceNumeric,
			    const char *protocol,
			    int err);

struct PortScanner;
struct PortScanner *newPortScanner(
	const char *host,
	in_port_t firstPort,
	in_port_t lastPort,
	int verbose,
	int servicesOnly,
	int maxSocket,
	FinishFunc,
	void *udata
	);

void deletePortScanner(struct PortScanner *);
int pollPortScanner(struct PortScanner *);
