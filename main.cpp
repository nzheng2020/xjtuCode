#include "include.h"

/*全局变量*/
set< vector<string> > glbpktsigSet;
char *globLogPath 	= "/home/nzheng/C++Projects/sigBox/THDataSet/Log/log0628.csv";
FILE *globLog	 	= fopen(globLogPath ,"a+");//全局log文件

/*运行：./SnorGen /home/nzheng/C++Projects/sigBox/DataSet/TrainingSet/traffic_train 0.2 1214*/
/*需要修改pktrulesGen.cpp规则文件目录路径*/
int main(int argc, char** argv)
{
	//char   		*RootPath = "/home/nzheng/C++Projects/sigBox/DataSet/sig_2M02";
	/*外部参数*/
	char   		*RootPath 		= argv[1];//训练集路径
	double		MinSupp 		= atof(argv[2]);//最小支持度参数
	char   		*outputname		= argv[3];//输出TrainingResult文件名
	double		pktMinSupp 		= MinSupp;//packet最小支持度
	////////////////The 52 varied to RootPath
	char 		*rulesName		= &RootPath[52];//规则文件名

	/*内部变量定义*/
	// int         file_num 		= 0;
	char        filePath[200] 	= {0};//训练集文件夹下pcap文件路径
	DIR         *dp 			= NULL;//文件类型变量
	//输出TrainingResult文件目录
	char 		*logRootPath 	= "/home/nzheng/C++Projects/sigBox/THDataSet/TrainingResult";
	//验证集目录
	char 		*validationPath	= "/home/nzheng/C++Projects/sigBox/validationSet";
	//白名单
	char 		WhiteSet[WhiteSetSize][WhiteSetSize]= {"\r\n\r\n","HTTP/1.1","Connection","Keep-Alive"};
	struct      dirent *dirp;//文件结构体
	/*计时变量*/
	struct 		timeval t_start,t_end, t_mid;
	double 		start, finish, mid, duration, midtime;
	gettimeofday(&t_start, NULL);
	//开始计时
	start = ((long)t_start.tv_sec)*1000+(long)t_start.tv_usec/1000;

	if ((dp = opendir(RootPath)) == NULL) {
		cout << "Open NULL!" <<endl;
		return 0;
	}
	/*开始log写入*/
	fprintf(globLog, "\n----------------------Login----------------------------\n");
	fprintf(globLog, "   %s  %lf  %s\n", RootPath, MinSupp, outputname);
	fflush(globLog);//刷新flush

	while ( dirp = readdir(dp) ) {
		/*拼接形成pacp文件完整路径*/
		if((strcmp(dirp->d_name, ".") == 0)||(strcmp(dirp->d_name, "..") == 0))
			continue;
		strcpy(filePath, RootPath);
		strcat(filePath, "/");
		strcat(filePath, dirp->d_name);

		#ifdef PRINT
		cout <<"FileName:"<< filePath <<endl;
		fprintf(globLog, "FileName:%s\n", filePath);
		fflush(globLog);
		#endif

		pcapParse(filePath);//解析pcap，解析结果存入全局变量ip_loadstr_map和ip_load_map
	}
	/*HostID个数*/
    cout <<"totalhost: "<< ip_loadstr_map.size() <<endl;
	fprintf(globLog, "totalhost:%d\n", ip_loadstr_map.size());
	fflush(globLog);

	set<string> SubSequenceSets = subsequenceExtractor(MinSupp);//生成content signature函数

	/*删除出现在白名单中的signature*/
	for (int i = 0; i < WhiteSetSize; ++i)
	{
		SubSequenceSets.erase(WhiteSet[i]);

	}
	/*转换存储格式，做为packet signature*/
	for (set<string>::iterator itj = SubSequenceSets.begin(); itj != SubSequenceSets.end(); ++itj){
		vector<string> tmp;
		tmp.push_back(*itj);
		glbpktsigSet.insert(tmp);
	}
	/*打印所有content signature*/
	printf("\n");
	for (set<string>::iterator iterset = SubSequenceSets.begin(); iterset != SubSequenceSets.end(); ++iterset){
		string sig = *iterset;
		int stateC = 0;
		for(string::iterator its = sig.begin(); its!= sig.end(); ++its){
			if(((int)*its > 32)&&((int)*its < 127)){
				if(stateC == 0)
					printf("%c", *its);
				else
					printf("|%c", *its);
				stateC = 0;
			}
			else{
				if(stateC == 0)
					printf("|%02x",(u_char)*its);
				else
					printf(" %02x",(u_char)*its);
				stateC = 1;
			}
		}
		if(stateC == 1)
			printf("|");
		printf("\n");
	}
	/*输出content signature生成时间*/
	gettimeofday(&t_mid, NULL);
	mid = ((long)t_mid.tv_sec)*1000+(long)t_mid.tv_usec/1000;
	midtime = double(mid - start)/1000;
	cout <<"********************************sigGenTime:"<< midtime <<"s**************************"<< endl;
	fprintf(globLog, "*******************sigGenTime:%lfs\n", midtime);
	fflush(globLog);
	/*生成packet signature*/
	set< vector<string> > pktsig = pktsequenceExtractor(SubSequenceSets,pktMinSupp);
	/*打印packet signature*/
	for (set< vector<string> >::iterator iterset = pktsig.begin(); iterset != pktsig.end(); ++iterset){
		vector<string> sigV = *iterset;
		for(vector<string>::iterator itstr = sigV.begin(); itstr!= sigV.end(); ++itstr){
			string sig = *itstr;
			int stateCp = 0;
			for(string::iterator its = sig.begin(); its!= sig.end(); ++its){
				if(((int)*its > 32)&&((int)*its < 127)){
					if(stateCp == 0)
						printf("%c", *its);
					else
						printf("|%c", *its);
					stateCp = 0;
				}
				else{
					if(stateCp == 0)
						printf("|%02x",(u_char)*its);
					else
						printf(" %02x",(u_char)*its);
					stateCp = 1;
				}
			}
			if(stateCp == 1)
				printf("|");
			printf("    ");
		}
		printf("\n");
	}
	/*拼接规则文件名*/
	std::ostringstream ss1,ss2;
	float f1 = realSupp;
	// float f2 = pktMinSupp;
	ss1 << f1*100;
	// ss2 << f2*100;
	const char *s1 = (ss1.str()).c_str();
	// const char *s2 = (ss2.str()).c_str();
	char rulesNameNew[200];
	string name(rulesName);
	string subname(name.substr(0, 8));
	strcpy(rulesNameNew,subname.c_str());
	strcat(rulesNameNew,"C");
	strcat(rulesNameNew,s1);
	// strcat(rulesNameNew,"P");
	// strcat(rulesNameNew,s2);

	printf("%s\n", rulesNameNew);
	pktrulesGen(pktsig,rulesNameNew);//生成规则文件

	cout << "MinSupp:" << realSupp <<endl;
	fprintf(globLog, "MinSupp:%lf\n", realSupp);
	fflush(globLog);

	/*输出程序运行结束时间*/
	gettimeofday(&t_end, NULL);
	finish = ((long)t_end.tv_sec)*1000+(long)t_end.tv_usec/1000;
	duration = double(finish - start)/1000;
	cout <<"**********************************Runing time is "<< duration << "s" <<endl;
	fprintf(globLog, "***************Runing time is:%lfs\n", duration);
	fflush(globLog);
	/*拼接形成csv文件名，并写入运行统计结果*/
	char logPath[200];
	strcpy(logPath, logRootPath);
	strcat(logPath, outputname);
	strcat(logPath, ".csv");
	FILE *resultFile = fopen(logPath ,"a+");
	fprintf(resultFile, "\r\n%s,%lf,%d,%d,%d,%lf,%lf,%lf,%lf,", argv[1], realSupp, ip_loadstr_map.size(), SubSequenceSets.size(), pktsig.size(), midtime, duration, L3time, S3num);
	fclose(resultFile);

	fclose(globLog);//关闭全局log文件

	return 1;
}
