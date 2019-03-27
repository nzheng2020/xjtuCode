#include "pcapParse.h"

void pcapParselocal(){
    char a[] = {0x21,0x22,0x00,0x24,0x25,0x00};
    std::vector<char> v( a,a + 6);
    string s1 = "userbobaccessusere";
    string s2 = "seraliceaccess";
    string s3 = "allusersofaccess";
    string s4 = "accessamount";
    //string s5 = "UaccessBuse";
    string s6 = "accesamountuser";
    string s7 = "accesamountuserof";
    string s5 = a;
    cout << "--------------" <<endl;
    copy(v.begin(), v.end(), ostream_iterator<char>(cout, " "));
    //string str1(v);
    //string str1(a,sizeof(a));
    // size_t b = str1.size();
    // cout << b <<endl;

    (ip_load_map)[1].push_back(s1);
    (ip_load_map)[2].push_back(s2);
    (ip_load_map)[3].push_back(s3);
    (ip_load_map)[4].push_back(s4);
    (ip_load_map)[5].push_back(s5);
    (ip_load_map)[6].push_back(s6);
    (ip_load_map)[6].push_back(s7);
    int count = ip_load_map[6].size();
    for (int i = 0;i < count; ++i){
        cout << ip_load_map[6][i] <<endl;
    }
}


void pcapParse(char *PCAP_FILE)
{
    u_int all_packet_num = 0;
    int src_port, dst_port;
    char src_ip[SIZE] = {0};
    char dst_ip[SIZE] = {0};
    /*pacp结构体*/
    pcap_header     pHeader;
    ip_header       *ipHeader;
    tcp_header      *tcpHeader;
    memset(src_ip, 0, SIZE);
    u_char *ippkt = NULL;
    FILE *fp = fopen(PCAP_FILE,"r");  //打开流量包
    if (fp == NULL) {
        printf("Open file-%s failed:%s\n",PCAP_FILE,strerror(errno));
        exit(0);
    }

    fseek(fp, 24, 0);//跳过pcap文件头
    while(1) {
        /*
        size_t fread ( void *buffer, size_t size, size_t count, FILE *stream) ;
        参 数
            buffer 用于接收数据的内存地址
            size 要读的每个数据项的字节数，单位是字节
            count 要读count个数据项，每个数据项size个字节
            stream 输入流
        返回值
            返回真实读取的项数，若大于count则意味着产生了错误。
            另外，产生错误后，文件位置指示器是无法确定的。
            若其他stream或buffer为空指针，或在unicode模式中写入的字节数为奇数，
            此函数设置errno为EINVAL以及返回0.
        */
        if(fread(&pHeader, sizeof(pcap_header), 1, fp) != 1)//读数据包头
        {
            break;
        }
        // int SIZE = 4;
        // char src_ip[SIZE],dst_ip[SIZE];
        all_packet_num ++;//test
        u_char *data = (u_char *)malloc(pHeader.capture_len + 1);
        memset(data, 0, pHeader.capture_len + 1);
        if(fread(data, pHeader.capture_len, 1, fp) != 1)
            break;
        data[pHeader.capture_len] = 0;//test
        if(pHeader.capture_len > len) {
            len = pHeader.capture_len;
        }
        if( !(data[12] == 0x08 && data[13] == 0x00 )) {
            if(data[12] == 0x81 && data[13] == 0x00) {
                if(data[16] == 0x08 && data[17] == 0x00) {
                    ippkt = data + 18;
                }else{
                    continue;
                }
            }else{
                continue;
            }
        } else{
            ippkt = data + 14;
        }//是IP包
          //跳到IP头
        ipHeader = (ip_header *)ippkt;
        inet_ntop(AF_INET, (void*)&(ipHeader->saddr), src_ip,16); //转换ip地址为点分制
        inet_ntop(AF_INET, (void *)&(ipHeader->daddr), dst_ip,16);
        // std::cout << src_ip << '\n';
        ipHeader->tlen = ntohs(ipHeader->tlen); //ntohs()函数将网络字节顺序转为主机字节顺序
        int ipHeaderLen = (ipHeader->ver_ihl & 0B00001111) * 4;
        if(ipHeader -> proto == 6) {
            //tcp
            ippkt = ippkt + ipHeaderLen;
            tcpHeader = (tcp_header*)ippkt;
            int tcpHeaderLen = (ntohs(tcpHeader->info_ctrl) >> 12) * 4;
            //?????????????
            if(ipHeader->tlen - ipHeaderLen == tcpHeaderLen){
                continue;
            }
            string load((char*)(ippkt + tcpHeaderLen), ipHeader->tlen - ipHeaderLen - tcpHeaderLen);
            unsigned int src_intip = (ipHeader->saddr);
            (ip_load_map)[src_intip].push_back(load);
            (ip_loadstr_map)[src_intip] += load;
        }
        else if(ipHeader->proto == 17) {
            //udp
            ippkt = ippkt + sizeof(ip_header);
            if (ipHeader->tlen - ipHeaderLen == 8)
            {
                continue;
            }
            //std::cout << ipHeader->tlen << " " << ipHeaderLen << '\n';
            if(ipHeader->tlen - ipHeaderLen - 8 < 0)
            {
                std::cout << all_packet_num << '\n';
                std::cout << "packet ERROR!" << '\n';
                std::cout << src_ip << '\n';
                continue;
            }
            string load((char*)(ippkt + 8), ipHeader->tlen - ipHeaderLen - 8);
            unsigned int src_intip = (ipHeader->saddr);
            (ip_load_map)[src_intip].push_back(load);
            (ip_loadstr_map)[src_intip] += load;

        }
        else{
            ippkt = ippkt + ipHeaderLen;
        }
        free(data);
    }
    fclose(fp);
    //return load;
}
