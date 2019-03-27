#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <iconv.h>
#include <errno.h>
#include "pcap.h"
#include <string.h>

#include <iterator>
#include <algorithm>
#include <cstring>

#include <fstream>
#include <cmath>
#include <iomanip>

#include <string>
#include <sys/io.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <map>
#include <set>
#include <list>
#include <algorithm>
// #include <mutex>

#include <sstream>
#include <math.h>
#include <vector>
using namespace std;

#define NUM_THREADS 8
#define WhiteSetSize 100
#define PRINT

struct thread_data{
   int  thread_id;
   set<string> message;
   float minSupp;

   set<string> pktSet;
   set<string> subpktSet;

   set< vector<string> > pktSets;

   set<string> messageReturn;
   set< vector<string> > pktSetReturn;
};

struct multRe{
    set<string> s1;
    set<string> s2;
};

/*函数申明*/
// bool TraverseFiles(string path, int &file_num);
// void pcapParselocal();
// float calSupport(string candidate);
// set<string> extractCandidate(set<string> S0 , size_t L);
// set< vector<string> > pktsignatureExtractor(set<string> signatureSet,float pktMinSupp);
// void *pktsuppfilterThread(void *threadarg);
void pcapParse(char *filname);//pcap解析函数
set<string> subsequenceExtractor(float MinSupp);//content signature生成函数
set< vector<string> > pktsequenceExtractor(set<string> signatureSet,float pktMinSupp);//packet signature生成函数
void pktrulesGen(set< vector<string> > pktsig,char *rulesName);//规则文件生成函数

/*外部变量*/
extern map<u_int, string > ip_loadstr_map;
extern set<string> SubSequenceSet;
extern double realSupp, L3time, S3num;
