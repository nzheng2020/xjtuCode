#ifndef __pcapParse_h
#define __pcapParse_h

#include "include.h"

#define SIZE   16
extern long len = 0;
map<u_int, vector< string > > ip_load_map;
map<u_int, string > ip_loadstr_map;

void pcapParse(char *PCAP_FILE);
void pcapParselocal();

#endif
