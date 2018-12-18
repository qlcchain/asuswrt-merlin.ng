/*************************************************************************
 *
 * Qlink VPN config 接口h文件
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

#ifndef _QLV_CONFIG_H
#define _QLV_CONFIG_H
#include "common_lib.h"

/*vpn服务状态*/
enum G_VPN_MODE_STATUS
{
    G_VPN_MODE_STATUS_IDLE = 0,
    G_VPN_MODE_STATUS_SERVER_START = 0x01,
    G_VPN_MODE_STATUS_SERVER_RUNNING,
    G_VPN_MODE_STATUS_SERVER_STOP,
    G_VPN_MODE_STATUS_CLIENT_START = 0x31,
    G_VPN_MODE_STATUS_CLIENT_RUNNING,
    G_VPN_MODE_STATUS_CLIENT_STOP,
    G_VPN_MODE_STATUS_BUTT,
};
//QLV模块命令字
enum QLV_CMD_ENUM
{
    QLV_CMD_VPN_STATUS_CHECK = 0x01,
    QLV_CMD_VPN_SERVER_START,
    QLV_CMD_VPN_SERVER_STOP,
    QLV_CMD_VPN_CLIENT_START,
    QLV_CMD_VPN_CLIENT_STOP,
    QLV_CMD_BUTT
};

#define QLV_SYSINFO_CHECK_CYCLE      600  //10* 60
#define QLV_HEARTBEAT_CYCLE      60  //60sec

int get_meminfo(void);
#endif
