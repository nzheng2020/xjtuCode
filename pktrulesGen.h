#ifndef __pktrulesGen_h
#define __pktrulesGen_h
#include "include.h"

extern map<u_int, vector< string > > ip_load_map;
void pktrulesGen(set< vector<string> > pktsig,char * rulesName);

#endif