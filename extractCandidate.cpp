#include "extractCandidate.h"
#include <iostream>
#include <cstring>
using namespace std;
set<string> extractCandidate(set<string> S0 , size_t L)
{
	std::set<string> S1;
	for (set<string>::iterator iterx = S0.begin(); iterx != S0.end(); ++iterx){
		string stx = *iterx;
		for (set<string>::iterator itery = S0.begin(); itery != S0.end(); ++itery){
			string sty = *itery;
			if( L == 1){
				string s = stx + sty;
				S1.insert(s);
			}
			else{
				int num = 0;
				for (int k = 1; k <= L-1 ; ++k){
					if(stx[k] == sty[k-1])
						++num;
				}
				if(num == L - 1){
					string s = stx + sty[L-1];
					S1.insert(s);
				}
			}
		}
	}
	return S1;
}

set< vector<string> > extractpktCandidate(set< vector<string> > pktS , size_t L)
{
	set< vector<string> > pktS0;
	clock_t 	start, finish, tmptime1,tmptime2;
	start = clock();
	int x = 0;
	for (set< vector<string> >::iterator iterx = pktS.begin(); iterx != pktS.end(); ++iterx,++x){
		int y = 0;
		for (set< vector<string> >::iterator itery = pktS.begin(); itery != pktS.end(); ++itery,++y){
			if( y > x ){
				int num = 0;
				set<string> tmp;
				for (int k = 0; k < L ; ++k){
					tmp.insert((*iterx)[k]);
					tmp.insert((*itery)[k]);
				}
				if(tmp.size() == L + 1){
					vector<string> tmpv;
					for(set<string>::iterator iter = tmp.begin(); iter != tmp.end(); ++iter){
						tmpv.push_back(*iter);
					}
		            pktS0.insert(tmpv);
				}
			}
		}
	}
	return pktS0;
}