#ifndef __subsequenceExtractor_h
#define __subsequenceExtractor_h

#include "include.h"

extern map<u_int, vector< string > > ip_load_map;
extern set<string> extractCandidate(set<string> S0 , size_t L);
extern float calSupport(string candidate ,float MinSupp);
extern set<string> calSuppFilter(set<string> S, float MinSupp);
extern float calpktSupport(vector<string> pktcandidate ,float pktMinSupp);
extern set< vector<string> > calpktSuppFilter(set< vector<string> > S, float pktMinSupp);
extern set< vector<string> > extractpktCandidate(set< vector<string> > pktS , size_t L);

extern set<string> calSuppFilter(set<string> S, float MinSupp, void *reT);

set<string> subsequenceExtractor(float MinSupp);
void *suppfilterThread(void *threadarg);
void *pktsuppfilterThread(void *threadarg);
set< vector<string> > pktsignatureExtractor(set<string> signatureSet,float pktMinSupp);
set< vector<string> > pktsigImpExtractor(set<string> subsigSet,set<string> signatureSet,float pktMinSupp);

#endif
