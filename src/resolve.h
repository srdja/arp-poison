
#ifndef _RESOLVE_H_
#define _RESOLVE_H_

#include <stdint.h>
#include <pcap.h>

#include "def.h"

ACP_STATUS resolve_remote_mac (pcap_t *p, Host *local, Host *remote, uint64_t timeout);
ACP_STATUS resolve_local      (char *dev, Host *host);

#endif
