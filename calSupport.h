#ifndef __calSupport_h
#define __calSupport_h
#include "include.h"
extern map<u_int, vector< string > > ip_load_map;
extern map<u_int, string > ip_loadstr_map;

float calSupport(string candidate ,float MinSupp);
float calpktSupport(vector<string> pktcandidate ,float pktMinSupp);
set<string> calSuppFilter(set<string> S, float MinSupp);
set<string> calSuppFilter(set<string> S, float MinSupp, void *reT);
set< vector<string> > calpktSuppFilter(set< vector<string> > S, float pktMinSupp);
#endif
