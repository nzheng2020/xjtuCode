#include "subsequenceExtractor.h"

set<string> SubSequenceSet;
extern set< vector<string> > glbpktsigSet;
extern FILE *globLog;

FILE *threadLog0 = fopen("/home/nzheng/C++Projects/sigBox/THDataSet/Log/thread0Log1212.csv" ,"a+");
FILE *threadLog1 = fopen("/home/nzheng/C++Projects/sigBox/THDataSet/Log/thread1Log1212.csv" ,"a+");
FILE *threadLog2 = fopen("/home/nzheng/C++Projects/sigBox/THDataSet/Log/thread2Log1212.csv" ,"a+");
FILE *threadLog3 = fopen("/home/nzheng/C++Projects/sigBox/THDataSet/Log/thread3Log1212.csv" ,"a+");
FILE *threadLog4 = fopen("/home/nzheng/C++Projects/sigBox/THDataSet/Log/thread4Log1212.csv" ,"a+");
FILE *threadLog5 = fopen("/home/nzheng/C++Projects/sigBox/THDataSet/Log/thread5Log1212.csv" ,"a+");
FILE *threadLog6 = fopen("/home/nzheng/C++Projects/sigBox/THDataSet/Log/thread6Log1212.csv" ,"a+");
FILE *threadLog7 = fopen("/home/nzheng/C++Projects/sigBox/THDataSet/Log/thread7Log1212.csv" ,"a+");

double realSupp = 1.0;
double S3num, L3time = 0;

void *suppfilterThread(void *threadarg)
{
	struct thread_data *my_data;
	my_data = (struct thread_data *) threadarg;

	set<string> S,S0;
	S = my_data->message;

	#ifdef PRINT
	/*计时相关变量*/
	struct timeval t_start,t_end, t_mid;
	double start,finish,duration;
	gettimeofday(&t_start, NULL);
	start = ((long)t_start.tv_sec)*1000+(long)t_start.tv_usec/1000;
	// cout << "\nThread ID : " << my_data->thread_id <<" in " <<endl;


	FILE *threadLog;
	threadLog = threadLog1;
	if (my_data->thread_id == 0)
		threadLog = threadLog0;
	else if (my_data->thread_id == 1)
		threadLog = threadLog1;
	else if (my_data->thread_id == 2)
		threadLog = threadLog2;
	else if (my_data->thread_id == 3)
		threadLog = threadLog3;
	else if (my_data->thread_id == 4)
		threadLog = threadLog4;
	else if (my_data->thread_id == 5)
		threadLog = threadLog5;
	else if (my_data->thread_id == 6)
		threadLog = threadLog6;
	else if (my_data->thread_id == 7)
		threadLog = threadLog7;


	fprintf(threadLog, "\nCONTENT In L: %d Num: %d ", (*(S.begin())).size(), S.size());
	fflush(threadLog);
	#endif

	S0 = calSuppFilter(S , my_data->minSupp);

	my_data->messageReturn = S0;

	#ifdef PRINT
	gettimeofday(&t_end, NULL);
	finish = ((long)t_end.tv_sec)*1000+(long)t_end.tv_usec/1000;
	duration = double(finish - start)/1000;
	cout << "\nThread ID : " << my_data->thread_id <<" exit! Time:" << duration <<" s"<<endl;

	fprintf(threadLog, "\nCONTENT Thread ID : %d exit! Time %lf s ", my_data->thread_id, duration);
	fflush(threadLog);
	#endif

	pthread_exit(NULL);
}

void *pktsuppfilterThread(void *threadarg)
{
	struct thread_data *my_data;
	my_data = (struct thread_data *) threadarg;

	#ifdef PRINT
	/*计时相关变量*/
	struct timeval t_start,t_end, t_mid;
	double start,finish,duration;
	gettimeofday(&t_start, NULL);
	start = ((long)t_start.tv_sec)*1000+(long)t_start.tv_usec/1000;

	FILE *threadLog;
	if (my_data->thread_id == 0)
		threadLog = threadLog0;
	else if (my_data->thread_id == 1)
		threadLog = threadLog1;
	else if (my_data->thread_id == 2)
		threadLog = threadLog2;
	else if (my_data->thread_id == 3)
		threadLog = threadLog3;
	else if (my_data->thread_id == 4)
		threadLog = threadLog4;
	else if (my_data->thread_id == 5)
		threadLog = threadLog5;
	else if (my_data->thread_id == 6)
		threadLog = threadLog6;
	else if (my_data->thread_id == 7)
		threadLog = threadLog7;

	fprintf(threadLog, "\nPACKET In L: %d Num: %d ", (*((my_data->pktSets).begin())).size(), (my_data->pktSets).size());
	fflush(threadLog);
	#endif

	my_data->pktSetReturn = calpktSuppFilter(my_data->pktSets,my_data->minSupp);

	#ifdef PRINT
	gettimeofday(&t_end, NULL);
	finish = ((long)t_end.tv_sec)*1000+(long)t_end.tv_usec/1000;
	duration = double(finish - start)/1000;
	cout << "Thread ID : " << my_data->thread_id <<" exit! Time:" << duration <<" s"<<endl;

	fprintf(threadLog, "\nPACKET Thread ID : %d exit! Time: %d s", my_data->thread_id, duration);
	fflush(threadLog);
	#endif
	pthread_exit(NULL);
}

/**
 * 特征提取函数
 * @method subsequenceExtractor
 * @param  MinSupp              [最小支持度阈值]
 * @return                      [特征集合]
 * @Author 	：zn
 */
set<string> subsequenceExtractor(float MinSupp)
{
	set<string> S,S0,S1,del;
	// thread struct
	pthread_t threads[NUM_THREADS];
	struct thread_data td[NUM_THREADS];
	int rc;
	/*产生单个字符过程*/
	string st,ch;
	for (int n = 0x00;n <= 0xff; n++){
		char a = n;
		st += a;
	}
	for(string::iterator its = st.begin(); its!= st.end(); ++its){
		//printf("%02x ",(u_char)*its);
		ch = *its;
		S.insert(ch);
	}

    size_t cnt = S.size();
    size_t L = 1;
    while(cnt != 0){
    	float supp;

		#ifdef PRINT
		//cout<< S.size() << "   filter (" << L << ") working..." << endl;
		fprintf(globLog, " %d  filter (%d) working...\n", S.size(), L);
		fflush(globLog);
		#endif

		struct 		timeval t_start,t_end, t_mid;
		double 		start, finish, mid, duration, midtime;
		gettimeofday(&t_start, NULL);
		start = ((long)t_start.tv_sec)*1000+(long)t_start.tv_usec/1000;

		/*数据筛选过程*/
    	if(S.size() < 300)//单线程
    		S0 = calSuppFilter(S, MinSupp);//根据最小支持度，过滤掉集合S中不满足支持度要求的字符串
    	else{//多线程
			map<int , set<string> > thd;
			int cnts = 0;
			/*将输入的集合NUM_THREADS等分*/
			for(set<string>::iterator it = S.begin(); it!= S.end(); ++it,++cnts){
				thd[cnts%NUM_THREADS].insert(*it);
			}
			/*创建线程，并构建输入*/
			for(int t = 0; t < NUM_THREADS; ++t){
				#ifdef PRINT
				cout <<"\nCreating thread... ID: " << t << " num:" << thd[t].size() <<endl;
				fprintf(globLog, "Creating thread... ID:%d num:%d\n", t, thd[t].size());
				fflush(globLog);
				#endif
				td[t].thread_id = t;
				td[t].message = thd[t];
				td[t].minSupp = MinSupp;
				rc = pthread_create(&threads[t], NULL, suppfilterThread, (void *)&td[t]);
				if (rc){
					cout << "Error:unable to create thread, ID: " << t << "return: " << rc << endl;
					exit(-1);
				}
			}

			/*等待所有线程退出，汇总过滤结果*/
			for(int t = 0; t < NUM_THREADS; ++t){
				pthread_join (threads[t],NULL);
				S0.insert((td[t].messageReturn).begin() ,(td[t].messageReturn).end() );
			}
		}

		/*满足最小支持度且长度大于2的字符串作为最终的候选特征存入SubSequenceSet，同时剔除具有包含关系的特征*/
		if ( L > 2 ) {
			for (set<string>::iterator itS = S0.begin(); itS != S0.end(); ++itS) {
				string can(*itS);
				for(set<string>::iterator its = SubSequenceSet.begin(); its!= SubSequenceSet.end(); its++){
					if (can.find(*its)!= string::npos){
						del.insert(*its);
					}
				}
				SubSequenceSet.insert(can);
			}
		}
		/*计时*/
		gettimeofday(&t_mid, NULL);
		mid = ((long)t_mid.tv_sec)*1000+(long)t_mid.tv_usec/1000;
		midtime = double(mid - start)/1000;

		cout <<"\nfilter completed! Time: " << midtime << endl;
		fprintf(globLog, "filter completed! Time: %lf s\n", midtime);
		fflush(globLog);

		if (L == 3) {
			L3time = midtime;
			S3num = S.size();
		}
		/*剔除具有包含关系的特征*/
		for(set<string>::iterator it = del.begin(); it != del.end(); ++it){
			SubSequenceSet.erase(*it);
		}
		del.clear();

		#ifdef PRINT
    	cout<< S.size() << "   filter " << S0.size() << " worked! Len:"<< L << endl;
		fprintf(globLog, "   filter %d worked! Len:%d  \n", S0.size(), L);
		fflush(globLog);
		#endif
    	//cout<< "filter time:" <<(double)(finish - start)/CLOCKS_PER_SEC <<"s"<<endl;

		/*数据拼接过程*/
		fprintf(globLog, " num:%d extract %d  to  %d   \n", S0.size(), L, L+1);
		fflush(globLog);
		//cout<< S0.size() <<"   extract " << L <<" to "<< L+1 <<" ..."<<endl;
    	S = extractCandidate(S0, L);//集合S0中参数为长度均为L的字符串，拼接为长度均为L+1的字符串，存入集合S1
    	L++ ;

		/*计时*/
		gettimeofday(&t_end, NULL);
		finish = ((long)t_end.tv_sec)*1000+(long)t_end.tv_usec/1000;
		duration = double(finish - mid)/1000;

		cout <<"\nextract completed! Time: " << duration << endl;
		fprintf(globLog, "extract completed! Time: %lf s\n", duration);
		fflush(globLog);

    	cnt = S.size();
    	S0.clear();
    }

    // if(SubSequenceSet.size() < 3){
    // 	SubSequenceSet = subsequenceExtractor(MinSupp - 0.1);
    // }
	if(MinSupp < realSupp)
		realSupp = MinSupp;
	return SubSequenceSet;
}

set< vector<string> > pktsequenceExtractor(set<string> signatureSet,float pktMinSupp)
{
	set< vector<string> > pktSet, pktSdel;
	// thread struct
	pthread_t threads[NUM_THREADS];
	struct thread_data td[NUM_THREADS];
	int rc;

	for(set<string>::iterator iterx = signatureSet.begin(); iterx != signatureSet.end(); ++iterx){
		vector<string> pktCan;
		pktCan.push_back(*iterx);

		pktSet.insert(pktCan);
		glbpktsigSet.insert(pktCan);
	}
	size_t cnt = pktSet.size();
	size_t L = 1;

    while(cnt != 0){


		#ifdef PRINT
		fprintf(globLog, "PACKET %d  filter (L:%d) working...\n", pktSet.size(), L);
		fflush(globLog);
		#endif
		/*计时*/
		struct 		timeval t_start,t_end, t_mid;
		double 		start, finish, mid, duration, midtime;
		gettimeofday(&t_start, NULL);
		start = ((long)t_start.tv_sec)*1000+(long)t_start.tv_usec/1000;

    	set< vector<string> > pktSet0;
    	if(pktSet.size() < 100){
    		set< vector<string> > tmpPkt = calpktSuppFilter(pktSet,pktMinSupp);
    		pktSet0.insert(tmpPkt.begin() ,tmpPkt.end() );
    	}
    	else{
			map<int , set< vector<string> > > thd;
			int cnts = 0;
			for(set< vector<string> >::iterator it = pktSet.begin(); it!= pktSet.end(); ++it,++cnts){
				thd[cnts%NUM_THREADS].insert(*it);
			}
			for(int t = 0; t < NUM_THREADS; ++t){
				#ifdef PRINT
				cout <<"\nCreating thread... ID: " << t << " num:" << thd[t].size() <<endl;
				#endif
				td[t].thread_id = t;
				td[t].pktSets = thd[t];
				td[t].minSupp = pktMinSupp;
				rc = pthread_create(&threads[t], NULL, pktsuppfilterThread, (void *)&td[t]);
				if (rc){
					cout << "Error:unable to create thread, ID: " << t << "return: " << rc << endl;
					exit(-1);
				}
			}
			for(int t = 0; t < NUM_THREADS; ++t){
				pthread_join (threads[t],NULL);
				pktSet0.insert((td[t].pktSetReturn).begin() ,(td[t].pktSetReturn).end() );
			}
		}

		/*计时*/
		gettimeofday(&t_mid, NULL);
		mid = ((long)t_mid.tv_sec)*1000+(long)t_mid.tv_usec/1000;
		midtime = double(mid - start)/1000;

		cout <<"\nPACKET filter completed! Time: " << midtime << endl;
		fprintf(globLog, "PACKET filter completed! Time: %lf s\n", midtime);
		fflush(globLog);

		std::cout << "deleting... " << '\n';
		/*删除包含关系的规则*/
		std::cout << "/* pktSet0.size(): */" << pktSet0.size() << "glbpktsigSet:" << glbpktsigSet.size() <<'\n';
		fprintf(globLog, "/* pktSet0.size(): */ %d glbpktsigSet:%d \n", pktSet0.size(), glbpktsigSet.size());
		fflush(globLog);

		for (set< vector<string> >::iterator itpS = pktSet0.begin(); itpS != pktSet0.end(); ++itpS) {
			vector<string> can = *itpS;
			size_t canlen = can.size();
			if (L != canlen)
				std::cout << "/* L != canlen */" << '\n';
			set<string> canS,canS0;

			copy(can.begin(), can.end(), inserter(canS, canS.end()));
			// for(vector<string>::iterator iter = can.begin(); iter != can.end(); ++iter)
			//     canS.insert(*iter);
			canS0 = canS;
			for(set< vector<string> >::iterator its = glbpktsigSet.begin(); its!= glbpktsigSet.end(); its++){
			    vector<string> pktsigV = *its;
			    /*for(vector<string>::iterator iters = pktsigV.begin(); iters != pktsigV.end(); ++iters)
			        canS.insert(*iters);
				std::cout << "canS.size():" << canS.size() << '\n';
			    if( (canS.size() == L) && (L != 1) )
			        pktSdel.insert(*its);
					canS = canS0;*/
				int Ltmp;
				for(vector<string>::iterator iters = pktsigV.begin(); iters != pktsigV.end(); ++iters) {
					canS.insert(*iters);
					Ltmp = canS.size();
					if(Ltmp != L)
						break;
				}
				// std::cout << "canS.size():" << Ltmp << '\n';
			    if( (Ltmp == L) && (L != 1) )
			        pktSdel.insert(*its);
			    canS = canS0;
			}
			glbpktsigSet.insert(can);
		}

		#ifdef PRINT
    	cout<< pktSet.size() << "   filter " << pktSet0.size() << " worked! Len:"<< L << endl;
    	#endif

		for(set< vector<string> >::iterator iti = pktSdel.begin(); iti != pktSdel.end(); ++iti)
			glbpktsigSet.erase(*iti);
		pktSdel.clear();

		//cout<< "extracting(" << pktSet0.size() << ")  " << L <<" to "<< L+1 <<"    ..."<<endl;

		pktSet = extractpktCandidate(pktSet0 ,L);

		/*计时*/
		gettimeofday(&t_end, NULL);
		finish = ((long)t_end.tv_sec)*1000+(long)t_end.tv_usec/1000;
		duration = double(finish - mid)/1000;

		cout <<"\nPACKET extract completed! Time: " << duration << endl;
		fprintf(globLog, "PACKET num:%d extract %d to %d completed! Time: %lf s\n",pktSet0.size(), L, L+1, duration);
		fflush(globLog);

    	L++ ;

    	cnt = pktSet.size();
    	if(!cnt)
    		cout<<"Null"<<endl;
    	pktSet0.clear();
    	//fclose(logFile);
    }

    // if(pktsignatureSet.size() == 0){
    // 	pktsignatureSet = pktsignatureExtractor(signatureSet,pktMinSupp - 0.05);
    // }
    // cout << "pktMinSupp:" << pktMinSupp <<endl;

	return glbpktsigSet;
}
