/*************************************************************************
 *
 * Qlink VPN main文件
 *
 * 
 * 
 * 
 * 
 *
 * 
 * 
 * 
 * 
 *
 * 
 * 
 *************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
	 
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define _WIN32_WINNT 0x501
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif	 
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <semaphore.h> 
#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/param.h>
#include <getopt.h>
#include <sys/socket.h>
#include <locale.h>
#include <dirent.h>
#include <errno.h> 
#include "ccompat.h"
#include "misc_tools.h"
#include "nTox.h"
#include "cJSON.h"
#include "qlv_config.h"
#include "common_lib.h"

static struct option long_opts[] = {
    {"help", no_argument, 0, 'h'},
    {"type", required_argument, 0, 't'},
    {"showqrcode", no_argument, 0, 's'},
    {"version", no_argument, 0, 'v'},
    {"dir", required_argument, 0, 'd'},
    {NULL, no_argument, NULL, 0},
};

const char *opts_str = "4bdeou:t:s:h:v:p:P:T:";
struct arg_opts_struct g_arg_opts;
char g_post_ret_buf[POST_RET_MAX_LEN] = {0};
char g_vpn_file_dir[VPN_FILE_DIR_MAX_LEN + 1] = {0};
struct vpn_server_list gVpnServerList;
int g_vpns1_enable = 0;
int g_vpns2_enable = 0;

extern int g_tox_stop;
extern char  homeDirPath[100];
extern void *tox_send_msg_thread(void *args);

/*************************************************************************
 *
 * Function name: set_default_opts
 * 
 * Instruction:qlv 设置默认启动参数
 * 
 * INPUT:none
 * 
 * 
 * OUPUT: none
 *
 *************************************************************************/
static void set_default_opts(void)
{
    memset(&g_arg_opts, 0, sizeof(g_arg_opts));
    /* set any non-zero defaults here*/
}
void print_usage(void)
{
    printf("command for example:\n");
    printf("\t win_server --showqrcode\n"); 
    printf("\t win_server --dir\n");
	printf("\t win_server --version\n");
    printf("\t win_server -h\n");
    printf("\n");
}
void print_version(void)
{
    printf("%d.%d.%d\n",
        QLV_SERVER_TOPVERSION,
        QLV_SERVER_MIDVERSION,
        QLV_SERVER_LOWVERSION);
}
/**********************************************************************************
  Function:      qrcode_show
  Description:   二维码文件显示在shell上
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:成功
                 1:失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/ 
int qrcode_show(void)
{
    char qrcode_buf[BUF_LINE_MAX_LEN+1] = {0};
    int ret_len =0;
    char cmd[BUF_LINE_MAX_LEN+1] = {0};
    char recv[BUF_LINE_MAX_LEN+1] = {0};
    FILE *fp = NULL;

    snprintf(cmd,BUF_LINE_MAX_LEN,"cat %s",QLV_P2PID_FILE);
    if (!(fp = popen(cmd, "r"))) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"popen cmd(%s) failed",cmd);
        return ERROR;
    }
    if (fgets(recv,BUF_LINE_MAX_LEN,fp) <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"failed cmd =%s",cmd);
        pclose(fp);
        return ERROR;
    }  
    pclose(fp);
    strncpy(qrcode_buf,recv,TOX_ID_STR_LEN);
    qlv_qrcode_create_utf8(qrcode_buf,NULL);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"qrcode_show ok");
    return OK;
}

/**********************************************************************************
  Function:      parse_args
  Description:  qlv 参数解析函数
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
static void parse_args(int argc, char *argv[])
{
    set_default_opts();

    int opt, indexptr;
    //long int port = 0;

    while ((opt = getopt_long(argc, argv, opts_str, long_opts, &indexptr)) != -1) 
    {
        switch (opt) 
        {
            case 'v':
    			print_version();
    			exit(EXIT_SUCCESS);
            case 's':
                qrcode_show();
    			exit(EXIT_SUCCESS);
			case 'd':
				strncpy(g_vpn_file_dir, optarg, VPN_FILE_DIR_MAX_LEN);
				break;
    		case 'h':
    		default:
    			print_usage();
    			exit(EXIT_SUCCESS);
                break;
        }
    }
}
/**********************************************************************************
  Function:      init_daemon
  Description:  切换为后台进程
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int init_daemon(void)
{ 
    int pid; 
    int i; 
 
    //忽略终端I/O信号，STOP信号
    signal(SIGTTOU,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGTSTP,SIG_IGN);
    signal(SIGHUP,SIG_IGN);
    
    pid = fork();
    if(pid > 0) {
        exit(0); //结束父进程，使得子进程成为后台进程
    }
    else if(pid < 0) { 
        return -1;
    }
 
    //建立一个新的进程组,在这个新的进程组中,子进程成为这个进程组的首进程,以使该进程脱离所有终端
    setsid();
 
    //再次新建一个子进程，退出父进程，保证该进程不是进程组长，同时让该进程无法再打开一个新的终端
    pid=fork();
    if( pid > 0) {
        exit(0);
    }
    else if( pid< 0) {
        return -1;
    }
 
    //关闭所有从父进程继承的不再需要的文件描述符
    for(i=0;i< NOFILE;close(i++));
 
    //改变工作目录，使得进程不与任何文件系统联系
    chdir("/tmp");
 
    //将文件当时创建屏蔽字设置为0
    umask(0);
 
    //忽略SIGCHLD信号
    signal(SIGCHLD,SIG_IGN); 
    
    return 0;
}
/**********************************************************************************
  Function:      signal_init
  Description:  信号量屏蔽
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int signal_init(void)
{ 
    //忽略终端I/O信号，STOP信号
    signal(SIGTTOU,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGTSTP,SIG_IGN);
    signal(SIGHUP,SIG_IGN);
 
    //改变工作目录，使得进程不与任何文件系统联系
    chdir("/tmp");
 
    //将文件当时创建屏蔽字设置为0
    umask(0);
 
    //忽略SIGCHLD信号
    signal(SIGCHLD,SIG_IGN); 
    return 0;
}

/**********************************************************************************
  Function:      daemon_exists
  Description:  检测并生成pid文件
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int daemon_exists(void)
{
	int fd;
	struct flock lock;
	char buffer[32];

	fd = open(QLV_DEAMON_PIDFILE, O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
	if (fd < 0) {
		return 0;
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(fd, F_SETLK, &lock) != 0) {
		close(fd);
		return 1;
	}

	ftruncate(fd, 0);
	snprintf(buffer, sizeof(buffer), "%d", getpid());
	write(fd, buffer, strlen(buffer));
	return 0;
}
/**********************************************************************************
  Function:      qlv_daemon_init
  Description:  qlv守护进程初始化
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int qlv_daemon_init(void)
{
	char cmd[1024] = {0};

    //建立通信管道
    unlink(QLV_FIFONAME);
    if (mkfifo(QLV_FIFONAME, 0777) == -1)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"qlv_daemon_init,mkfifo error %s", strerror(errno));
		return ERROR;
    }

    //建立用户目录
    if(access(QLV_TOPDIR,F_OK) != OK)
    {
        snprintf(cmd, sizeof(cmd), "mkdir -p %s", QLV_TOPDIR);
        system(cmd);
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "system err (%s)", cmd);
    } 
    
    return ERROR;
}

/**********************************************************************************
  Function:      tox_daemon
  Description:  tox守护进程，负责基础的p2p网络组建，接收winq的消息
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
static void *tox_daemon(void *para)
{
    //gethomedir();
    CreatedP2PNetwork();
	return NULL;
}
/**********************************************************************************
  Function:      monstat_daemon
  Description:  状态检测守护进程，负责系统整体状态检测
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
static void *monstat_daemon(void *para)
{
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"monstat_daemon in ");
    while(1)
    {
        get_meminfo();
        sleep(QLV_SYSINFO_CHECK_CYCLE);
    }
	return NULL;
}
/**********************************************************************************
  Function:      heartbeat_daemon
  Description:  心跳守护进程，负责维系心跳
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
static void *heartbeat_daemon(void *para)
{
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"heartbeat_daemon in ");
    while(1)
    {
        Heartbeat();
        sleep(QLV_HEARTBEAT_CYCLE);
    }
	return NULL;
}

/**********************************************************************************
  Function:      qlv_getvpn_list_bycountry
  Description:  根据
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int qlv_getvpn_list_bycountry(char* country)
{
	char tmp_buf[BUF_LINE_MAX_LEN] = {0};
	char post_field[BUF_LINE_MAX_LEN] = {0};
    char timestamp_string[VPN_TIMESTAMP_MAX_LEN] = {0};
    char md5_sign[ENCRYPTION_TYPE_MAXLEN] = {0};
    int i = 0,num = 0;
    char* tmp_json_buff = NULL;
	cJSON * root =  cJSON_CreateObject();
    cJSON * params =  cJSON_CreateObject();

    if(root == NULL || params == NULL || country == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"qlv_getvpn_list_bycountry:json create err");
        return ERROR;
    }
    snprintf(timestamp_string,VPN_TIMESTAMP_MAX_LEN,"%d",(int)time(NULL));
    //param json fmt
    cJSON_AddItemToObject(params, "country", cJSON_CreateString(country));
    
    //组建序列串，生成md5_sign
    QLV_PUT_PARAMSRING(tmp_buf,"appid","MIFI",FALSE);
    tmp_json_buff = cJSON_PrintUnformatted(params);
    if(tmp_json_buff != NULL)
    {
        QLV_PUT_PARAMSRING(tmp_buf,"params",tmp_json_buff,TRUE);
        free(tmp_json_buff);
    }
    QLV_PUT_PARAMSRING(tmp_buf,"timestamp",timestamp_string,TRUE);
	//DEBUG_PRINT(DEBUG_LEVEL_ERROR,"qlv_get_md5sign:md5_sign(%s)",tmp_buf);
	qlv_get_md5sign(tmp_buf,md5_sign);

    //json格式化
    cJSON_AddItemToObject(root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(timestamp_string));
    cJSON_AddItemToObject(root, "params", params);
    cJSON_AddItemToObject(root, "sign", cJSON_CreateString(md5_sign));

    tmp_json_buff = cJSON_PrintUnformatted(root);
    if(tmp_json_buff != NULL)
    {
        snprintf(post_field,BUF_LINE_MAX_LEN,"%s",tmp_json_buff);
        free(tmp_json_buff);
	}
    cJSON_Delete(root);
    root = NULL;
	//http post
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"post_info_to_idc:post_field(%s)",post_field);
	memset(g_post_ret_buf,0,POST_RET_MAX_LEN);
	if(post_info_to_idc(QLV_IDC_HOST,QLV_IDC_QUERY_VPN_V3,post_field,g_post_ret_buf) <= 0)
	{
	    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"post_info_to_idc:ret failed");
	    return ERROR;
	}
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"post_info_to_idc:get ret(%s)",g_post_ret_buf);
	//返回参数解析
    root = cJSON_Parse(g_post_ret_buf);
    if(root == NULL) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"qlv_getvpn_list_bycountry:get root failed");
        return ERROR;
    }
    params = cJSON_GetObjectItem(root, "data");
    if((params == NULL))
    {
        cJSON_Delete(root);
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"qlv_getvpn_list_bycountry:get params failed");
        return ERROR;
    }
    cJSON* arr_item = params->child;
    cJSON* tmp_item = NULL;
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"qlv_getvpn_list_bycountry:get params keyword(%s)arr_item(%s)",params->string,arr_item->string);
    cJSON* vpnlist = cJSON_GetObjectItem(arr_item,"vpnList");
    if(vpnlist == NULL)
    {
        cJSON_Delete(root);
        //cJSON_Delete(params);
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"qlv_getvpn_list_bycountry:get vpnlist failed");
        return ERROR;         
    }
    num = cJSON_GetArraySize(vpnlist);
    if(num <= 0)
    {
        cJSON_Delete(root);
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"qlv_getvpn_list_bycountry:get vpnlist num(%d) failed",num);
        return ERROR;         
    }
    else if(num > VPN_NODE_MAX_NUM)
    {
        DEBUG_PRINT(DEBUG_LEVEL_NORMAL,"qlv_getvpn_list_bycountry:get vpnnode(%d),too much",num);
        num = VPN_NODE_MAX_NUM;
    }
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"qlv_getvpn_list_bycountry:get vpnnode(%d)",num);
    arr_item = vpnlist->child;//子对象

    for(i=0;i<num;i++)
    {
        QLV_CJSON_GET_VARSTR_BYKEYWORD(arr_item,tmp_item,tmp_json_buff,"vpnName",gVpnServerList.vpnNode[i].vpnName,VPN_NAME_MAX_LEN);
        QLV_CJSON_GET_VARSTR_BYKEYWORD(arr_item,tmp_item,tmp_json_buff,"country",gVpnServerList.vpnNode[i].country,VPN_COUNTRY_MAX_LEN);
        QLV_CJSON_GET_VARSTR_BYKEYWORD(arr_item,tmp_item,tmp_json_buff,"p2pId",gVpnServerList.vpnNode[i].p2pId,VPN_P2PID_MAX_LEN);
        QLV_CJSON_GET_VARSTR_BYKEYWORD(arr_item,tmp_item,tmp_json_buff,"address",gVpnServerList.vpnNode[i].address,VPN_ADDRESS_MAX_LEN);
        QLV_CJSON_GET_VARFLOAT_BYKEYWORD(arr_item,tmp_item,tmp_json_buff,"qlc",gVpnServerList.vpnNode[i].currentQlc,VPN_TIMESTAMP_MAX_LEN);
        QLV_CJSON_GET_VARFLOAT_BYKEYWORD(arr_item,tmp_item,tmp_json_buff,"registerQlc",gVpnServerList.vpnNode[i].registerQlc,VPN_TIMESTAMP_MAX_LEN);
        QLV_CJSON_GET_VARFLOAT_BYKEYWORD(arr_item,tmp_item,tmp_json_buff,"cost",gVpnServerList.vpnNode[i].cost,VPN_NAME_MAX_LEN);
        QLV_CJSON_GET_VARINT_BYKEYWORD(arr_item,tmp_item,tmp_json_buff,"connectNum",gVpnServerList.vpnNode[i].connectNum,VPN_NAME_MAX_LEN);
        QLV_CJSON_GET_VARFLOAT_BYKEYWORD(arr_item,tmp_item,tmp_json_buff,"bandWidth",gVpnServerList.vpnNode[i].bandWidth,VPN_TIMESTAMP_MAX_LEN);
        QLV_CJSON_GET_VARINT_BYKEYWORD(arr_item,tmp_item,tmp_json_buff,"connsuccessNum",gVpnServerList.vpnNode[i].connsuccessNum,VPN_NAME_MAX_LEN);
        QLV_CJSON_GET_VARINT_BYKEYWORD(arr_item,tmp_item,tmp_json_buff,"onlineTime",gVpnServerList.vpnNode[i].onlineTime,VPN_NAME_MAX_LEN);
        QLV_CJSON_GET_VARSTR_BYKEYWORD(arr_item,tmp_item,tmp_json_buff,"heartTime",gVpnServerList.vpnNode[i].heartTime,VPN_ADDRESS_MAX_LEN);
        QLV_CJSON_GET_VARSTR_BYKEYWORD(arr_item,tmp_item,tmp_json_buff,"effectiveTime",gVpnServerList.vpnNode[i].effectiveTime,VPN_ADDRESS_MAX_LEN);
#if 1
        DEBUG_PRINT(DEBUG_LEVEL_NORMAL,"vpnnode[%d] -- vpnname(%s) country(%s) p2pId(%s) address(%s) qlc(%d) registerQlc(%d) cost(%d) connectNum(%d) bandWidth(%d) connsuccessNum(%d) onlineTime(%d) heartTime(%s) effectiveTime(%s)",
            i,gVpnServerList.vpnNode[i].vpnName,gVpnServerList.vpnNode[i].country,gVpnServerList.vpnNode[i].p2pId,gVpnServerList.vpnNode[i].address,gVpnServerList.vpnNode[i].currentQlc,gVpnServerList.vpnNode[i].registerQlc,
            gVpnServerList.vpnNode[i].cost,gVpnServerList.vpnNode[i].connectNum,gVpnServerList.vpnNode[i].bandWidth,gVpnServerList.vpnNode[i].connsuccessNum,gVpnServerList.vpnNode[i].onlineTime,gVpnServerList.vpnNode[i].heartTime,gVpnServerList.vpnNode[i].effectiveTime);
#endif
        if(arr_item && i<num)
            arr_item = arr_item->next;//下一个子对象
    }
	cJSON_Delete(root);
    //cJSON_Delete(params);
    //cJSON_Delete(arr_item);
    //cJSON_Delete(vpnlist);
    return OK;
}

/**********************************************************************************
  Function:      qlv_msg_deal
  Description:  上报消息处理入口
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others:

  History: 1. Date:2012-03-07
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
void qlv_msg_deal(char * pbuf,int msg_len)
{
	int msg_type = 0;
	msg_type = atoi(pbuf);
	pbuf = strchr(pbuf,0x20);
	if(pbuf == NULL)
	{
		DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad msg_type param %d",pbuf);  
		return;
	}
	pbuf ++;
	msg_len -= 2;
	//DEBUG_PRINT(DEBUG_LEVEL_INFO,"qlv_msg_deal len(%d) msg(%s)",msg_len,pbuf); 
	switch(msg_type)
	{
	    case QLV_CMD_VPN_STATUS_CHECK:
            break;
        case QLV_CMD_VPN_SERVER_START:
            break;
 	    case QLV_CMD_VPN_SERVER_STOP:
            break;
        case QLV_CMD_VPN_CLIENT_START:
            break;
        case QLV_CMD_VPN_CLIENT_STOP:
            break;
		default:
			DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad msg_type param %d",msg_type);  
			break;
	}
	return;
}

/**********************************************************************************
  Function:      fifo_msg_handle
  Description:  消息处理
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others:

  History: 1. Date:2012-03-07
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
static int fifo_msg_handle(void)
{
    int fpipe;
    char line[BUF_LINE_MAX_LEN] = {0};
    char* pbuf;
	int line_len = 0;
    char* p_end = NULL;
	
	fpipe = open(QLV_FIFONAME, O_RDONLY);
	//监听管道
	while(1)
    {	
    	line_len = read(fpipe, line, BUF_LINE_MAX_LEN);
        //消息结构体是类似 "3 XXXX"
		if(line_len >= 3)
		{
			if(line[line_len-1] == '\n')
			{
				line[line_len-1] = 0;
				line_len = line_len-1;
			}
			//DEBUG_PRINT(DEBUG_LEVEL_INFO,"fifo_msg_handle %d (%s)",line_len,line);  
			pbuf = &line[0];
			p_end = NULL;
			p_end = strchr(pbuf,'\n');
			if(p_end != NULL)
			{
				//DEBUG_PRINT(DEBUG_LEVEL_INFO,"###########################################"); 
				//DEBUG_PRINT(DEBUG_LEVEL_INFO,"get len(%d) msg(%s)",line_len,pbuf); 
				while(1)
				{
					p_end[0] = 0;
					qlv_msg_deal(pbuf,p_end-pbuf);
					pbuf = p_end +1;
					p_end = NULL;
					p_end = strchr(pbuf,'\n');
					if(p_end == NULL)
					{
						qlv_msg_deal(pbuf,&line[line_len]-pbuf);
						break;
					}
				}
			}
			else
			{
				qlv_msg_deal(pbuf,line_len);
			}
		}
		else if(line_len == 0)
		{
			usleep(100);
			continue;
		}
		else
		{
    		DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad return (%d)",line_len); 
		    usleep(500);
			memset(line,0,BUF_LINE_MAX_LEN);
			/*close(fpipe);
			unlink(QLV_FIFONAME);
  		    if (mkfifo(QLV_FIFONAME, 0777) == -1)
  		    {
  		        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"mkfifo error %s\n", strerror(errno));
  				return ERROR;
  		    }
			fpipe = open(QLV_FIFONAME, O_RDONLY);*/
			continue;
		}
		memset(line,0,BUF_LINE_MAX_LEN);
    }
	close(fpipe);
    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"fifo exit");  
	return OK;
}

/*****************************************************************************
 函 数 名  : nvram_get
 功能描述  : 读取nvram配置
 输入参数  : char *name  
 输出参数  : 无
 返 回 值  : char
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年12月14日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
char *nvram_get(char *name)
{
	static char nvram_result[16] = {0};
	FILE *pf = NULL;
	char cmd[256] = {0};

	memset(nvram_result, 0, sizeof(nvram_result));
	snprintf(cmd, sizeof(cmd), "nvram get %s", name);
	pf = popen(cmd, "r");
	if (pf) {
		fgets(nvram_result, sizeof(nvram_result) - 1, pf);
		pclose(pf);
		return nvram_result;
	}

	return NULL;
}

/*****************************************************************************
 函 数 名  : nvram_get_int
 功能描述  : 获取int类型配置
 输入参数  : char *name  
             int *value  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年12月14日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int nvram_get_int(char *name, int *value)
{
	char nvram_result[16] = {0};
	FILE *pf = NULL;
	char cmd[256] = {0};

	snprintf(cmd, sizeof(cmd), "nvram get %s", name);
	pf = popen(cmd, "r");
	if (pf) {
		fgets(nvram_result, sizeof(nvram_result) - 1, pf);
		pclose(pf);

		*value = strtoul(nvram_result, NULL, 0);
		return 0;
	}

	return -1;
}

/*****************************************************************************
 函 数 名  : openvpn_monitor_thread
 功能描述  : 监测openvpn运行情况
 输入参数  : void *args  
 输出参数  : 无
 返 回 值  : void
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年12月14日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
void *openvpn_monitor_thread(void *args)
{
	pthread_t tox_tid;
	char vpns1_md5_last[33] = {0};
	char vpns2_md5_last[33] = {0};
	char vpns1_md5_now[33] = {0};
	char vpns2_md5_now[33] = {0};
	char changed = 0;
	
	while (1) {
		nvram_get_int("vpn_server1_state", &g_vpns1_enable);
		nvram_get_int("vpn_server2_state", &g_vpns2_enable);
		changed = 0;

		if (!g_vpns1_enable && !g_vpns2_enable) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "all servers closed");
			g_tox_stop = 1;

			system("rm -f /jffs/winq_server/client1.ovpn");
			system("rm -f /jffs/winq_server/client2.ovpn");
			memset(vpns1_md5_last, 0, 33);
			memset(vpns2_md5_last, 0, 33);

			sleep(60);
			continue;
		}

		if (g_tox_stop == 1) {
			g_tox_stop = 0;
			
			/*启动tox进程，建立P2P网络*/
			if (pthread_create(&tox_tid, NULL, tox_daemon,NULL) != OK) {
		        return ERROR;
			}
		}

		if (g_vpns1_enable) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "server1 enabled");
			if (access("/etc/openvpn/server1/client.ovpn", F_OK) == OK) {
				md5_hash_file("/etc/openvpn/server1/client.ovpn", vpns1_md5_now);
				
				DEBUG_PRINT(DEBUG_LEVEL_ERROR, "server1 (%s---%s)", vpns1_md5_now, vpns1_md5_last);
				if (memcmp(vpns1_md5_now, vpns1_md5_last, 32)) {
					DEBUG_PRINT(DEBUG_LEVEL_ERROR, "vpn server1 config changed");

					memcpy(vpns1_md5_last, vpns1_md5_now, 32);
					system("cp /etc/openvpn/server1/client.ovpn /jffs/winq_server/client1.bak");
					changed = 1;
				}
			}
		} else {
			system("rm -f /jffs/winq_server/client1.ovpn");
			memset(vpns1_md5_last, 0, 33);
		}

		if (g_vpns2_enable) {
			if (access("/etc/openvpn/server2/client.ovpn", F_OK) == OK) {
				md5_hash_file("/etc/openvpn/server2/client.ovpn", vpns2_md5_now);
				if (memcmp(vpns2_md5_now, vpns2_md5_last, 32)) {
					DEBUG_PRINT(DEBUG_LEVEL_ERROR, "vpn server2 config changed");
					
					memcpy(vpns2_md5_last, vpns2_md5_now, 32);
					system("cp /etc/openvpn/server2/client.ovpn /jffs/winq_server/client2.bak");
					changed = 1;
				}
			}
		} else {
			system("rm -f /jffs/winq_server/client2.ovpn");
			memset(vpns2_md5_last, 0, 33);
		}

		if (changed) {
			system("ovpn_ip_update /jffs/winq_server 1");
			system("mv /jffs/winq_server/client1.bak /jffs/winq_server/client1.ovpn");
			system("mv /jffs/winq_server/client2.bak /jffs/winq_server/client2.ovpn");
		}
		
		sleep(60);
	}
}

/*****************************************************************************
 函 数 名  : openvpn_updateip_thread
 功能描述  : 周期更新ip地址
 输入参数  : void *args  
 输出参数  : 无
 返 回 值  : void
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2019年1月14日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
void *openvpn_updateip_thread(void *args)
{
	while (1) {
		system("/jffs/winq_server/ovpn_ip_update /jffs/winq_server/");
		sleep(60);
	}
}

/**********************************************************************************
  Function:      main
  Description:  qlv主入口函数，负责输入参数解析，启动任务等
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int32 main(int argc,char *argv[])
{
    pthread_t tox_tid;
    pthread_t monstat_tid;
    pthread_t heartbeat_tid;

    DEBUG_INIT(LOG_PATH);
    DEBUG_LEVEL(DEBUG_LEVEL_INFO);
	parse_args(argc, argv);
	
	system("mkdir -p /jffs/winq_server");
	strncpy(g_vpn_file_dir, "/jffs/winq_server", VPN_FILE_DIR_MAX_LEN);

	if (!g_vpn_file_dir[0]) {
		printf("please specify the config file directory\n");
		printf("win_server --dir xx\n");
		return ERROR;
	}

	if (!opendir(g_vpn_file_dir)) {
		printf("dir not exist [%s]\n", g_vpn_file_dir);
		return ERROR;
	}
	
    signal_init();

	if (daemon_exists()) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "main exit");
        exit(1);
    }

	qlv_daemon_init();
	init_daemon();

    //心跳线程
    if (pthread_create(&heartbeat_tid, NULL, heartbeat_daemon, NULL) != 0)
    {
        return ERROR;
    }   

	/*启动monitor_stat进程，监控系统资源使用情况*/
    if (pthread_create(&monstat_tid, NULL, monstat_daemon, NULL) != 0) 
    {
        return ERROR;
    }

    /* 消息发送线程 */
    if (pthread_create(&tox_tid, NULL, tox_send_msg_thread, NULL) != OK)
	{
        return ERROR;
	}

	/* 监视openvpn运行 */
	if (pthread_create(&tox_tid, NULL, openvpn_monitor_thread, NULL) != OK)
	{
        return ERROR;
	}

	/* update wan ipaddr periodically */
	if (pthread_create(&tox_tid, NULL, openvpn_updateip_thread, NULL) != OK)
	{
        return ERROR;
	}

    fifo_msg_handle();

exit:
    return OK;
}

