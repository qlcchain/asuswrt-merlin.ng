#ifndef COMMON_LIB_H
#define COMMON_LIB_H

#ifndef OK
#define OK 0
#endif

#ifndef ERROR
#define ERROR 1
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

typedef  unsigned char uint8;
typedef  unsigned short uint16;
typedef  unsigned int uint32;
typedef  char int8;
typedef  short int16;
typedef  int int32;
typedef  unsigned long long uint64;
typedef  long long int64;

#define RETRY_SEND_MAXTIME 5
#define MAC_LEN 6
#define IPSTR_MAX_LEN 64
#define MACSTR_MAX_LEN 18
#define VERSION_MAXLEN   32
#define URL_MAX_LEN 1024
#define BUF_LINE_MAX_LEN 2048
#define ENCODEBUF_LINE_MAX_LEN 4096
#define POST_RET_MAX_LEN 40960
#define TIMESTAMP_STRING_MAXLEN  128
#define MANU_NAME_MAXLEN 256
#define MANU_CODE_MAXLEN 256
#define ENCRYPTION_TYPE_MAXLEN 64
#define ENCRYPTION_KEY_MAXLEN 256
#define VPN_FILE_DIR_MAX_LEN 512

#define ID_TYPE_STRING_MAXLEN 4
#define ID_CODE_STRING_MAXLEN 128
#define DEFAULT_DES_KEYLEN   8
#define TOX_ID_STR_LEN   76
#define LOGINTIME_PAYLOAD "XXXXXXXXXXXXXXXXXXX" //yyyy-MM-dd HH:mm:ss
#define LOGINTIME_PAYLOAD_LEN 19 //yyyy-MM-dd HH:mm:ss
#define LOGINTIME_PAYLOAD2 "XXXXXXXXXXXXXX" //yyyyMMddHHmmss
#define LOGINTIME_PAYLOAD2_LEN 14 //yyyyMMddHHmmss

#define LOGINTIME_PAYLOAD2_OFFSET (LOGINTIME_PAYLOAD_LEN+1)
#define QLV_CMD_MAXLEN 1024
#define QLV_DEAMON_PIDFILE  "/tmp/winq_server.pid"
#define LOG_PATH "/tmp/logdisk/winq_server.log"
#define QLV_FIFONAME  "/tmp/winq_server.fifo"
#define QLV_OPEN_FIFONAME_CMD  "cat /tmp/winq_server.fifo"
#define QLV_PUT_PARAMSRING(str,key,var,flag)   qlv_put_params_string(str,key,var,flag)
#define QLV_TOPDIR      "/jffs/winq_server/"
#define QLV_P2PID_FILE 	"/jffs/winq_server/p2pid.txt"
#define QLV_TOXP2PID_PNGFILE "/jffs/winq_server/winq.png"
#define QLV_SERVER_TOPVERSION 1
#define QLV_SERVER_MIDVERSION 0
#define QLV_SERVER_LOWVERSION 1

#define USERDEBUG
enum DEBUG_LEVEL
{
    DEBUG_LEVEL_INFO         = 1,
    DEBUG_LEVEL_NORMAL,
    DEBUG_LEVEL_ERROR,
};

#ifdef USERDEBUG
#define DEBUG_INIT(file) log_init(file)
#define DEBUG_LEVEL(level) log_level(level)
#define DEBUG_PRINT(level,format...)\
log_print_to_file(level, __FILE__, __LINE__,format)
#else
#define DEBUG_PRINT(level,format...) //do{printf(format);printf("\n");}while(0)
#endif

typedef struct curl_buf
{
	char * pos;
	char * buf;
	unsigned int len;
}tCurlBuf;
struct arg_opts_struct {
    char version_flag;
    char help_flag;
    char qrcode_showmode;
};
#define VPN_NAME_MAX_LEN  128
#define VPN_COUNTRY_MAX_LEN  32
#define VPN_P2PID_MAX_LEN 128
#define VPN_ADDRESS_MAX_LEN 128
#define VPN_TIMESTAMP_MAX_LEN  32

#define VPN_NODE_MAX_NUM   64

#define QLV_COUNTRY_NAME_US "United States"
#define QLV_COUNTRY_NAME_UK "United Kingdom"
#define QLV_COUNTRY_NAME_SGP "Singapore"
#define QLV_COUNTRY_NAME_JP "Japan"
#define QLV_COUNTRY_NAME_SWL "Switzerland"
#define QLV_COUNTRY_NAME_GEM "Germany"
#define QLV_COUNTRY_NAME_OTHER "Others"
#define QLV_IDC_HOST  "dapp-t.qlink.mobi"
#define QLV_IDC_QUERY_VPN_V3 "/api/neo/vpn/queryVpnV3.json"
#define QLV_CJSON_GET_VARSTR_BYKEYWORD(item,tmpItem,tmp_json_buff,key,var,len) \
    {\
        tmpItem=cJSON_GetObjectItem(item,key);\
        if(tmpItem != NULL)\
        {\
            tmp_json_buff = cJSON_PrintUnformatted(tmpItem);\
            if(tmp_json_buff != NULL)\
            {\
                strncpy(var,tmp_json_buff,len);\
                free(tmp_json_buff);\
            }\
        }\
        else\
        {\
            memset(var,0,len);\
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get key(%s) failed",key);\
        }\
    }
#define QLV_CJSON_GET_VARFLOAT_BYKEYWORD(item,tmpItem,tmp_json_buff,key,var,len) \
    {\
        tmpItem=cJSON_GetObjectItem(item,key);\
        if(tmpItem != NULL)\
        {\
            tmp_json_buff = cJSON_PrintUnformatted(tmpItem);\
            if(tmp_json_buff != NULL)\
            {\
                var=(int)(atof(tmp_json_buff) * 100);\
                free(tmp_json_buff);\
            }\
        }\
        else\
        {\
            var = 0;\
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get key(%s) failed",key);\
        }\
    }
#define QLV_CJSON_GET_VARINT_BYKEYWORD(item,tmpItem,tmp_json_buff,key,var,len) \
    {\
        tmpItem=cJSON_GetObjectItem(item,key);\
        if(tmpItem != NULL)\
        {\
            tmp_json_buff = cJSON_PrintUnformatted(tmpItem);\
            if(tmp_json_buff != NULL)\
            {\
                var = atoi(tmp_json_buff);\
                free(tmp_json_buff);\
            }\
        }\
        else\
        {\
            var = 0;\
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get key(%s) failed",key);\
        }\
    }

struct vpn_server_node
{
    int cost;
    int registerQlc;
    int currentQlc;
    int connectNum;
    int connsuccessNum;
    int onlineTime;
    int bandWidth;
    char vpnName[VPN_NAME_MAX_LEN];
    char country[VPN_COUNTRY_MAX_LEN];
    char p2pId[VPN_P2PID_MAX_LEN];
    char address[VPN_ADDRESS_MAX_LEN];
    char heartTime[VPN_TIMESTAMP_MAX_LEN];
    char effectiveTime[VPN_TIMESTAMP_MAX_LEN];
};
struct vpn_server_list
{
    int vpnNodeNum;
    struct vpn_server_node vpnNode[VPN_NODE_MAX_NUM];
};
#define QLV_APPID  "MIFI"
#define QLV_MD5_KEYWORD  "05cd19c64d5f4faabd27c74607fd1f51"
//function declaration
int get_cmd_ret(char* pcmd);
//unsigned int ip_aton(const char* ip);
//char* ip_ntoa(unsigned int ip);
char *mac_to_str(unsigned char *mac);
void log_init(char *file);
void log_level(int level);
int log_print_to_file(int level, char* file,int line,char *fmt,...);
int check_ip_string(const char *ip);
unsigned int convert_str2ip(const char *ipaddr);
int post_info_to_idc(char *host, char *url, char *post_fields, char *ret_buf);
int urlencode(char* str,int strSize, char* result, const int resultSize);
unsigned char* urldecode(unsigned char* encd,unsigned char* decd);
int cjson_get_keyword_string(char* pbuf,char* pkey,char* pret);
int cjson_ret_stauts_check(char * pbuf);
int strtotime(char* datetime);
int qlv_put_params_string(char* string,char* key,char* value,int appendflag);
int qlv_get_md5sign(char* src_string,char* out_sign);
int qlv_qrcode_create_png(char* src_string,char* dst_filename);
int qlv_qrcode_create_utf8(char* src_string,char* dst_filename);
#endif

