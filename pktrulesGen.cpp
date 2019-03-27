#include "pktrulesGen.h"

/**
 * [pktrulesGen 生成规则文件]
 * @method pktrulesGen
 * @param  pktsig      [packet signature集合]
 * @param  rulesName   [规则文件名]
 * @Author 	：zn
 * 修复content中出现 ： ； / " ( ) 会报错的bug
 */
void pktrulesGen(set< vector<string> > pktsig,char *rulesName)
{
	int count = 1000000;
	set<int> offsets;
	vector<int> offset;
	vector<int> depth;

	char *rulesrootPath = "/home/nzheng/C++Projects/sigBox/THDataSet/Rules/1214/";//规则文件路径
	char rulesPath[200];
	strcpy(rulesPath,rulesrootPath);
	strcat(rulesPath,rulesName);
	strcat(rulesPath,".rules");
	FILE *pFile = fopen(rulesPath,"w+");//规则文件

	for(set< vector<string> >::iterator it = pktsig.begin(); it != pktsig.end(); ++it){
		vector<string> Sig = *it;
		count++;
		fprintf(pFile , "alert tcp any any -> any any (msg:\"TEST\";sid:%d",count);
		/*开始计算offset和depth*/
		for(vector<string>::iterator its = Sig.begin(); its != Sig.end(); ++its){
			string signature(*its);
			size_t siglen = signature.size();
			int of = 10000,de = 0;
			for(map<u_int, vector< string > >::iterator iter =  ip_load_map.begin(); iter != ip_load_map.end(); ++iter){
		        int loadnum = (iter->second).size();
		        for (int i = 0;i < loadnum; ++i){
		            string load = (iter->second)[i];
		            size_t fi = load.find(signature);
		            while(fi != string::npos){
		            	if(fi < of)
		            		of = fi;
		            	if(fi > de)
		            		de = fi;
		                offsets.insert(fi);
		                fi = load.find(signature,fi + 1);
		            }
		        }
			}

			fprintf(pFile, ";content:\"");

			size_t lsig = 0;

			/*二进制/字符混合规则*/
			int stateC = 0;
			for(string::iterator itst = signature.begin(); itst != signature.end(); ++itst){
				if(((int)*itst > 31)&&((int)*itst < 127) &&((int)*itst != 58)&&((int)*itst != 59)&&((int)*itst != 47)&&((int)*itst != 34)&&((int)*itst != 40)&&((int)*itst != 41)&&((int)*itst != 124)&&((int)*itst != 92) ){
					if(stateC == 0)
						fprintf(pFile, "%c", *itst);
					else
						fprintf(pFile, "|%c", *itst);
					stateC = 0;
				}
				else{
					if(stateC == 0)
						fprintf(pFile, "|%02x",(u_char)*itst);
					else
						fprintf(pFile, " %02x",(u_char)*itst);
					stateC = 1;
				}
				lsig++;
			}
			if(stateC == 1)
				fprintf(pFile, "|");
			/*二进制/字符混合规则*/

			/*二进制规则文件*/
			// fprintf(pFile, "|");
			// for(string::iterator itst = signature.begin(); itst != signature.end(); ++itst){
			// 	fprintf(pFile, "%02x ",(u_char)*itst);
			// 	lsig++;
			// }
			// fseek(pFile, -1 ,SEEK_CUR);
			// fprintf(pFile, "|");
			/*二进制规则文件*/


			fprintf(pFile, "\";offset:%d;depth:%d", of, (de + lsig - of));
		}
		fprintf(pFile , ";)\r\n");
	}
	fclose(pFile);
}
