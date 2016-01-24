#ifndef _SPOOF_H_
#define _SPOOF_H_

#include <pcap.h>
#include "def.h"

void spoof_init (pcap_t *pcap_h, Host targets[TARGETS], Host *local, bool grat);
int  spoof_run  (void);

#endif
