#include <iostream>
#include <string>
#include <pcap/pcap.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <pcl/point_types.h>
#include <pcl/point_cloud.h>
#include <pcl/io/pcd_io.h>
#include "config.h"

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
#define SNAP_LEN 1518       // 以太网帧最大长度
#define SIZE_ETHERNET 14   // 以太网包头长度，其中MAC地址为 6*2, type占 2字节，共14字节
#define ETHER_ADDR_LEN  6  // mac地址长度
#define SIZE_UDP 8          // UDP头部长度
#define SIZE_PCAP   16      // PCAP头部长度

using namespace std;

void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

template<typename T>
inline T str2num(string str);

template<typename T>
inline string num2str(T num);

/* IP header */
struct packet_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
    #define IP_RF 0x8000            /* reserved fragment flag */
    #define IP_DF 0x4000            /* dont fragment flag */
    #define IP_MF 0x2000            /* more fragments flag */
    #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

pcl::PointCloud<pcl::PointXYZI> cloud;
string output_folder;
int pcd_count = 0;
ofstream f_out;

int main(int argc, char** argv)
{
    if(argc < 2)
    {
        cout << "usage: VLP-reader pcap_file [start_timestamp] [end_timestamp]" << endl;
        return 0;
    }

    double start_timestamp = 0;
    double end_timestamp = numeric_limits<double>::max();
    if(argc > 2)
        start_timestamp = str2num<double>(string(argv[2]));
    if(argc > 3)
        end_timestamp = str2num<double>(string(argv[3]));
    
    
    string::size_type pos = string(argv[1]).rfind('/');
    if(pos == -1)
        output_folder = "./lidar/";
    else 
        output_folder = string(argv[1]).substr(0, pos) + "/lidar/";
    if(!boost::filesystem::exists(output_folder))
        boost::filesystem::create_directory(output_folder);

    f_out.open("lidar_timestamp.txt");
    
    char ebuf[PCAP_ERRBUF_SIZE];
    // 传到回调函数里两个参数，第一个参数是用来统计当前是第几个packet，第二个参数是当前packet的时间戳
    u_char arg[sizeof(size_t) + 2*sizeof(double)] = {0};
    *(double*)(arg + sizeof(size_t)) = start_timestamp;
    *(double*)(arg + sizeof(size_t) + sizeof(double)) = end_timestamp;
    
    pcap_t *p = pcap_open_offline(argv[1], ebuf);
    struct pcap_pkthdr pkthdr;
    pcap_loop(p, -1, loop_callback, (u_char*)arg);
    pcap_close(p);
    if(!cloud.empty())
    {
        pcd_count++;
        cout << pcd_count << endl;
        pcl::io::savePCDFileASCII(output_folder + "/" + num2str(pcd_count) + ".pcd", cloud);
        cloud.clear();
        f_out << "pcd : " << pcd_count << ".pcd, time stamp : " <<  *(double*)(arg + sizeof(size_t)) << endl;
    }
    f_out.close();
    return 0;
}

void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    
    const ethhdr *ethernet;  /* The ethernet header [1] */
    const struct packet_ip *ip;              /* The IP header */
    const udphdr* udp;                       /* The UDP header */
    int size_ip;        // ip 头的长度
    size_t* counter = (size_t*)(args);
    double* last_timestamp = (double*)(args + sizeof(size_t));
    const double* end_timestamp = (double*)(args + sizeof(size_t) + sizeof(double));

    // 如果上一帧结束之后的时间戳已经达到了设定的结尾，那么就直接return即可
    if(*last_timestamp >= *end_timestamp)
        return;
    
    // 512 字节的是Position Packet，一般是外接了其他设备时候使用的，比如GPS IMU等
    // 这里只有雷达，所以直接跳过
    if(header->len != 1206 + SIZE_ETHERNET + SIZE_UDP + 20)
    {
        (*counter)++;
        return ;
    }
    double curr_timestamp = header->ts.tv_sec + header->ts.tv_usec / 1000000.0;

    // 如果没给定初始的时间戳，那就把第一帧时间戳当做初始的
    if(*last_timestamp <= 0)
        *last_timestamp = curr_timestamp;
    /* 以太网头 */
    ethernet = (ethhdr*)(packet);

    /* IP头 */
    ip = (struct packet_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        cout << "无效的IP头长度: "<<  size_ip  << " bytes" << endl;
        return;
    }

    // 必须得是UDP协议才正确
    if ( ip->ip_p != IPPROTO_UDP )
    { 
        cout << "protocal is not UDP, wrong. protocal is " << int(ip->ip_p) << endl;
        return ;
    }


    /* UDP 头*/
    udp = (udphdr*)(packet + SIZE_ETHERNET + size_ip);
    int source_port = ntohs(udp->source);
    int target_port = ntohs(udp->dest);
    // cout << "source_port : " << source_port << ", target port: " << target_port << endl;

    // 这是12个data block起始的位置
    int data_start = SIZE_ETHERNET + SIZE_UDP + size_ip;
    const u_char* mode = (u_char*)(packet + data_start + 1204);
    if(*mode == DUAL_RETURN )
    {
        cout << "dual return mode is not support" << endl;
        return;
    }
    
    int offset = data_start;
    // 一共有12个block
    for(int block_id = 0; block_id < 12; block_id++)
    {
        // 注意这里的0xFFEE是低位 FF 高位 EE，因此在比较的时候，要反过来，因为高位在前，低位在后，所以是 0xEEFF
        assert(*(uint16_t*)(packet + offset) == 0xEEFF);
        // 4字节，保存的是 标志位 0xFFEE 以及 角度
        offset += 4;
        const uint16_t* angle = (uint16_t*)(packet + offset + 2);
        float block_alpha = *angle * 0.01;
        if(block_alpha >= 360.0)
            block_alpha -= 360.0; 
        // 每个block里有2个sequence
        for(int seq_id = 0; seq_id < 2; seq_id ++)
        {
            if(curr_timestamp < *last_timestamp)
            {
                offset += 3 * SCANS;
                curr_timestamp += SCANS * FIRING_CYCLE / 1000000.0;
                goto next_block;
            }
            for(int laser_id = 0; laser_id < SCANS; laser_id++)
            {
                float distance = *(uint16_t*)(packet + offset) * 0.002;     // 这里保存的距离是 2mm为单位的
                offset += 3;            // 每个点是3个字节保存的
                if(distance == 0)
                    continue;
                u_char reflection = *(packet + offset + 2);
                float point_alpha = block_alpha + laser_id * FIRING_CYCLE / 1000000.0 * HORIZON_SPEED;
                point_alpha *= M_PI / 180.0;
                float x = distance * sin(point_alpha) * cos(vertical_angle[laser_id]);
                float y = distance * cos(point_alpha) * cos(vertical_angle[laser_id]);
                float z = distance * sin(vertical_angle[laser_id]);
                pcl::PointXYZI pt(reflection);
                pt.x = x;
                pt.y = y;
                pt.z = z;
                cloud.push_back(pt);
                curr_timestamp += FIRING_CYCLE / 1000000.0;
                // 一旦超过了时间阈值，就保存一下点云
                if(curr_timestamp - *last_timestamp >= PCD_DURATION)
                {
                    pcd_count ++;
                    cout << pcd_count << endl;
                    pcl::io::savePCDFileASCII(output_folder + "/" + num2str(pcd_count) + ".pcd", cloud);
                    cloud.clear();
                    f_out << fixed << setprecision(6) << "pcd : " << pcd_count << ".pcd, time stamp : " << (*last_timestamp) << endl;

                    *last_timestamp = curr_timestamp;
                }
            }
            next_block:
            block_alpha += SEQUENCE_TIME / 1000000.0 * HORIZON_SPEED;
            curr_timestamp += RECHARGEING_TIME / 1000000.0;
            // 一旦超过了时间阈值，就保存一下点云
            if(curr_timestamp - *last_timestamp >= PCD_DURATION)
            {
                pcd_count ++;
                cout << pcd_count << endl;
                pcl::io::savePCDFileASCII(output_folder + "/" + num2str(pcd_count) + ".pcd", cloud);
                cloud.clear();
                f_out << fixed << setprecision(6) << "pcd : " << pcd_count << ".pcd, time stamp : " << (*last_timestamp) << endl;

                *last_timestamp = curr_timestamp;
            }
        } 
    }
    
    (*counter)++;

}

template<typename T>
inline T str2num(string str)
{
    T num;
    stringstream sin(str);
    if(sin >> num) {
        return num;
    }
    else{
        cout << "str2num error";
        exit(0);
    }
}

template<typename T>
inline string num2str(T num)
{
    ostringstream oss;
    if (oss << num) {
        string str(oss.str());
        return str;
    }
    else {
        cout << "num2str error" << endl;
        exit(0);
    }
}