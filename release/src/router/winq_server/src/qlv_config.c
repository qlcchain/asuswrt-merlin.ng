/*************************************************************************
 *
 * Qlink VPN config 接口C文件
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
#include <errno.h> 
#include "common_lib.h"
#include "qlv_config.h"

int g_mem_total = 0;
int g_mem_free = 0;
/**********************************************************************************
  Function:      get_meminfo
  Description:  获取内存使用情况
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
int get_meminfo(void)
{
    char cmd[QLV_CMD_MAXLEN] = {0};
    char recv[QLV_CMD_MAXLEN] = {0};
    FILE *fp = NULL;

    if(g_mem_total == 0)
    {
#ifdef ARCH_X86
        snprintf(cmd,QLV_CMD_MAXLEN,"cat /proc/meminfo |grep MemTotal");
#else
        snprintf(cmd,QLV_CMD_MAXLEN,"cat /proc/meminfo |grep MemTotal");
#endif
        if (!(fp = popen(cmd, "r"))) 
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get_meminfo popen cmd(%s) failed",cmd);
            return ERROR;
        }
        if (fgets(recv,QLV_CMD_MAXLEN,fp) <= 0)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get_meminfo failed cmd =%s",cmd);
            pclose(fp);
            return ERROR;
        }  
        pclose(fp);
        g_mem_total = atoi(&recv[10]);
    }

#ifdef ARCH_X86
    snprintf(cmd,QLV_CMD_MAXLEN,"cat /proc/meminfo |grep MemFree");
#else
    snprintf(cmd,QLV_CMD_MAXLEN,"cat /proc/meminfo |grep MemFree");
#endif
    if (!(fp = popen(cmd, "r"))) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get_meminfo popen cmd(%s) failed",cmd);
        return ERROR;
    }
    if (fgets(recv,QLV_CMD_MAXLEN,fp) <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get_meminfo failed cmd =%s",cmd);
        pclose(fp);
        return ERROR;
    }  
    pclose(fp);
    g_mem_free = atoi(&recv[10]);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"get_meminfo: MemTotal(%d) MemFree(%d)",g_mem_total,g_mem_free);
    return OK;
}


