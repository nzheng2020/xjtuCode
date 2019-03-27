#include "calSupport.h"

/**
 * 计算候选子序列candidate的支持度
 * @method calSupport
 * @param  candidate  [候选子序列]
 * @param  MinSupp    [最小支持度阈值]
 * @return            [支持度值]
 * @Author     ：zn
 */
float calSupport(string candidate ,float MinSupp)
{
    float supphost   = 0.0;
    float totalhost  = ip_load_map.size();
    float Uhosts     = (1 - MinSupp)*totalhost;//最多不满足条件的HostID个数
    float Shosts     = MinSupp*totalhost;//最少满足条件的HostID个数

    int cc = 0;//用于记录已经遍历过的HostID的个数
    for(map<u_int, vector< string > >::iterator it = ip_load_map.begin(); it != ip_load_map.end(); ++it){
        cc++;
        int loadnum = (it->second).size();//当前HostID的payload个数
        for (int i = 0;i < loadnum; ++i){//遍历当前HostID的payload
            string load = (it->second)[i];
            if (load.find(candidate) != string::npos){//判断候选子序列是否在当前HostID的payloads中
                ++supphost;//找到当前HostID下第一个包含该候选子序列candidate的payload就退出，计数加一
                break;
            }
        }
        /*提前退出的情况*/
        if((supphost >= Shosts)||((cc-supphost) > Uhosts)){
            return supphost/totalhost ;
        }
    }
    return supphost/totalhost ;
}

/**
 * 过滤不满足支持度要求的字符串
 * @method calSuppFilter
 * @param  S             [输入待过滤的字符串集合S]
 * @param  MinSupp       [最小支持度参数]
 * @return               [过滤后的字符串集合S0]
 * @Author     ：zn
 */
set<string> calSuppFilter(set<string> S, float MinSupp)
{
    set<string> S0;

    for(set<string>::iterator it = S.begin(); it!= S.end(); it++){
        string can(*it);
        float supp = calSupport(can ,MinSupp);//逐个计算支持度
        if(supp >= MinSupp){
            S0.insert(can);//满足最小支持度则存入S0
        }
    }
    return S0;
}

/**
 * [calpktSupport 计算单个packet signature的支持度]
 * @method calpktSupport
 * @param  pktcandidate  [候选特征]
 * @param  pktMinSupp    [最小支持度]
 * @return               [支持度值]
 * @Author     ：zn
 */
float calpktSupport(vector<string> pktcandidate ,float pktMinSupp)
{
    float supphost   = 0.0;
    float totalhost  = ip_load_map.size();
    float Uhosts     = (1 - pktMinSupp)*totalhost;//最大不满足的个数
    float Shosts     = pktMinSupp*totalhost;//最大满足的个数

    map<u_int, vector< string > >::iterator it;
    it = ip_load_map.begin();
    int cc = 0;
    while(it != ip_load_map.end()){
        cc++;
        int loadnum = (it->second).size();//当前pktSignature包含的conSignature个数
        for (int i = 0;i < loadnum; ++i){
            string load = (it->second)[i];//第i个数据包
            int count = 0;
            for(vector<string>::iterator iter = pktcandidate.begin(); iter!= pktcandidate.end(); iter++){
                if (load.find(*iter) != string::npos){
                    count++;
                }
                else
                    break;
            }
            if (count == pktcandidate.size()){
                supphost++;
                break;
            }
        }
        /*提前退出情况*/
        if((supphost >= Shosts)||((cc-supphost) > Uhosts)){
            return supphost/totalhost ;
        }

        ++it;
    }
    return supphost/totalhost ;
}
/**
 * [calpktSuppFilter 过滤packet signature]
 * @method calpktSuppFilter
 * @param  S                [packet signature集合]
 * @param  pktMinSupp       [最小支持度]
 * @Author     ：zn
 */

set< vector<string> > calpktSuppFilter(set< vector<string> > S, float pktMinSupp)
{
    set< vector<string> > S0;
    for(set< vector<string> >::iterator it = S.begin(); it!= S.end(); it++){
        vector<string> can = *it;
        float supp = calpktSupport(can ,pktMinSupp);//计算当前packet signature的支持度
        if(supp >= pktMinSupp){
            S0.insert(can);//过滤后的集合S0
        }
    }
    return S0;
}
