#ifndef _SPOOF_H_
#define _SPOOF_H_

#include <pcap.h>
#include "def.h"

void reply_spoof_init (pcap_t *pcap_h, Host targets[TARGETS], Host *local, bool grat);
int  reply_spoof_run  (void);
int  reply_spoof_stop (void);

#endif
