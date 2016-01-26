#ifndef _SPOOF_H_
#define _SPOOF_H_

#include <pcap.h>
#include "def.h"

void spoof_init (pcap_t *pcap_h, Host targets[TARGETS], Host *local, bool grat, bool use_request);
int  spoof_run  (void);
int  spoof_stop (void);

#endif
