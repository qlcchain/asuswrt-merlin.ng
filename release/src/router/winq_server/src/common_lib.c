#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <common_lib.h>
#include <curl/curl.h>
#include <sys/file.h>
#include "md5.h"

char log_path[64];
int g_debug_level = DEBUG_LEVEL_ERROR;

#define AUTHUSERCMDPARSELINE(buff,phead,ptail,line,fp)\
{\
    phead =strchr(buff,':');\
    if(phead == NULL)\
    {\
        pclose(fp);\
        return ERROR;\
    }\
    phead ++;\
    ptail = strchr(phead,';');\
    if(ptail == NULL)\
    {\
        pclose(fp);\
        return ERROR;\
    }\
    ptail[0] = '\0';\
}
int get_cmd_ret(char* pcmd)
{
    int line = 0;
    long int ret = 0;
    FILE *fp = NULL;
    char *p_head = NULL;
    char * p_tail = NULL;
    char buff[BUF_LINE_MAX_LEN];

    memset(buff, 0, sizeof(buff));
    
    if(pcmd == NULL)
    {
        return ERROR;
    }

    if (!(fp = popen(pcmd, "r"))) 
    {
        return ERROR;
    }

    while(NULL != fgets(buff, BUF_LINE_MAX_LEN, fp)) 
    {
        if(line == 0)
        {
            AUTHUSERCMDPARSELINE(buff,p_head,p_tail,line,fp);
            ret = strtol(p_head, (char **) NULL, 16);
            if(ret != OK)
            {
                pclose(fp);
                return ERROR;
            }
            break;
        }
    }

    pclose(fp);
    return OK;
}

#if 0
unsigned int ip_aton(const char* ip)
{
	struct in_addr ip_addr;
	if( inet_aton(ip, &ip_addr) )
    {   
		return ip_addr.s_addr;
    }   
	return OK;
}

char* ip_ntoa(unsigned int ip)
{
	struct in_addr ip_addr;

    ip_addr.s_addr = htonl(ip);  
	return inet_ntoa(ip_addr);
}
#endif
char *mac_to_str(unsigned char *mac)
{
	static char str[32];

	memset(str, 0x00, sizeof(str));
	sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X", 
        (unsigned int)mac[0], 
        (unsigned int)mac[1], 
        (unsigned int)mac[2], 
        (unsigned int)mac[3], 
        (unsigned int)mac[4], 
        (unsigned int)mac[5]);
	return str;
}

void log_init(char *file)
{
    memset(log_path, 0, sizeof(log_path));
    strcpy(log_path, file);
}

void log_level(int level)
{
    g_debug_level = level;
}

int log_print_to_file(int level, char* file,int line,char *fmt,...)
{
    va_list args;
    //time_t t = time(NULL);
    char time_str[TIMESTAMP_STRING_MAXLEN] = {0};
    //struct tm date;
    //struct tm* tp;
    FILE *log_fp = NULL;
    int fd_no = 0;
    //memset(time_str, 0, TIMESTAMP_STRING_MAXLEN);

    if(g_debug_level > level)
    {
        return ERROR;
    }
    	
    //tp= localtime_r(&t,&date);
    if((log_fp = fopen(log_path, "a")) == NULL)
    {
        return ERROR;
    }
    fd_no = fileno(log_fp);
    flock(fd_no,LOCK_EX);
	//strftime(time_str,100,"[%Y-%m-%d-%H:%M:%S] ",tp);
	snprintf(time_str,TIMESTAMP_STRING_MAXLEN,"[%s:%d %d]",file,line,(int)time(NULL));
	//snprintf(time_str,TIMESTAMP_STRING_MAXLEN,"[  ]");
    fprintf(log_fp,"%s",time_str);
    va_start(args,fmt);
    vfprintf(log_fp,fmt,args);
    va_end(args);
    fprintf(log_fp,"\n");
    fclose(log_fp);
    flock(fd_no, LOCK_UN);
    return OK;
}


int check_ip_string(const char *ip)
{
    int  i = 0,  len = strlen(ip);

    for(; i < len; ++i)
    {
        if(! ((ip[i] <= '9' && ip[i] >= '0') ||(ip[i] == '.')))
        {
             return  -1;
        }
    }
    return OK;
}

unsigned int convert_str2ip(const char *ipaddr)
{
	unsigned int b[4]= {0,0,0,0};

	sscanf(ipaddr, "%u.%u.%u.%u", &b[0], &b[1], &b[2], &b[3]);
	return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}

static size_t post_idc_func( void *ptr, size_t size, size_t nmemb, void *stream)
{
	tCurlBuf * buf;
	int tmp_len = 0;
	buf = (tCurlBuf *)stream;
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"post_idc_func:buf len(%d) nmemb(%d)",buf->len,nmemb);
	if(buf->len + nmemb >= POST_RET_MAX_LEN)
	{
		tmp_len = POST_RET_MAX_LEN - 1 - buf->len;
		if(tmp_len <= 0)
		{
			return 0;
		}
	}
	else
	{
		tmp_len = nmemb;
	}
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"post_idc_func:tmplen(%d) buf(%s)",tmp_len,ptr);
	memcpy(buf->pos,ptr,tmp_len);
	buf->pos[tmp_len] = 0;
	buf->pos += tmp_len;
	buf->len += tmp_len;
	//DEBUG_PRINT(DEBUG_LEVEL_INFO,"post_idc_func:get total buflen(%d)",buf->len);
	return tmp_len;
}
int post_info_to_idc(char *host, char *url, char *post_fields, char *ret_buf)
{
	CURLcode return_code;
	CURL *easy_handle;
	char t_url[1024] = {0};
	tCurlBuf buf;
	int ret_len = -1;
	struct curl_slist* headers = NULL;
	
	easy_handle = curl_easy_init();
	snprintf(t_url,1024,"http://%s%s",host,url);
	curl_easy_setopt(easy_handle, CURLOPT_URL,t_url);
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"post_info_to_idc:post t_url(%s)",t_url);

	buf.buf = ret_buf;
	buf.pos = ret_buf;
	buf.len = 0;
	curl_easy_setopt(easy_handle,CURLOPT_WRITEFUNCTION,post_idc_func);

	//设置http发送的内容类型为JSON
    //构建HTTP报文头  
	//增加HTTP header
	headers = curl_slist_append(headers, "Accept:application/json");
	headers = curl_slist_append(headers, "Content-Type:application/json");
	headers = curl_slist_append(headers, "charset:utf-8");
	curl_easy_setopt(easy_handle, CURLOPT_HTTPHEADER, headers);
	//curl_easy_setopt(easy_handle,CURLOPT_HEADER,0);

	curl_easy_setopt(easy_handle,CURLOPT_WRITEDATA,&buf);
	curl_easy_setopt(easy_handle,CURLOPT_POST, 1);
	curl_easy_setopt(easy_handle,CURLOPT_POSTFIELDS, post_fields);
	curl_easy_setopt(easy_handle,CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(easy_handle,CURLOPT_CONNECTTIMEOUT, 10);
	curl_easy_setopt(easy_handle,CURLOPT_TIMEOUT, 5);
    curl_easy_setopt(easy_handle, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"post_info_to_idc:set post_fields(%s)",post_fields);
	return_code = curl_easy_perform(easy_handle);
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"post_info_to_idc:return_code(%d)",return_code);
	if (CURLE_OK != return_code)
	{
		ret_len = 0;
		goto exit;
	}
	ret_len = buf.pos - buf.buf;

exit:
	curl_slist_free_all(headers); /* free the list again */
	curl_easy_cleanup(easy_handle);	
	return ret_len;
}

/**********************************************************************************
  Function:      urlencode
  Description:  字符串的url编码
  Calls:
  Called By:
  Input:         char* str
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int urlencode(char* str,int strSize, char* result, const int resultSize)
{
    int i;
    int j = 0;
    char ch;
 
    if ((str==NULL) || (result==NULL) || (strSize<=0) || (resultSize<=0)) 
    {
        return -1;
    }
 
    for ( i=0; (i<strSize)&&(j<resultSize); ++i) 
	{
        ch = str[i];
        if (((ch>='A') && (ch<'Z')) ||
            ((ch>='a') && (ch<'z')) ||
            ((ch>='0') && (ch<'9'))) 
	    {
            result[j++] = ch;
        } 
		else if (ch == ' ') 
		{
            result[j++] = '+';
        } 
		else if (ch == '.' || ch == '-' || ch == '_' || ch == '*')
		{
            result[j++] = ch;
        } 
		else 
		{
            if (j+3 < resultSize) 
            {
                sprintf(result+j, "%%%02X", (unsigned char)ch);
                j += 3;
            } 
            else 
            {
                return -1;
            }
        }
    }
 
    result[j] = '\0';
    return j;
}

//解url编码实现 
unsigned char* urldecode(unsigned char* encd,unsigned char* decd) 
{ 
    int j,i; 
    char *cd = (char*)encd; 
    char p[2]; 
    //unsigned int num; 
	j=0; 

    for( i = 0; i < strlen(cd); i++ ) 
    { 
        if( cd[i] != '%' ) 
        { 
            decd[j++] = cd[i]; 
            continue; 
        } 
        memset( p, 0, 2);   
  		p[0] = cd[++i]; 
        p[1] = cd[++i]; 

        p[0] = p[0] - 48 - ((p[0] >= 'A') ? 7 : 0) - ((p[0] >= 'a') ? 32 : 0); 
        p[1] = p[1] - 48 - ((p[1] >= 'A') ? 7 : 0) - ((p[1] >= 'a') ? 32 : 0); 
        decd[j++] = (unsigned char)(p[0] * 16 + p[1]); 
    }  
    return decd; 
}

int cjson_get_keyword_string(char* pbuf,char* pkey,char* pret)
{
	char ptmp_buff[BUF_LINE_MAX_LEN] = {0};
	char* ptmp = NULL;
	char* pend = NULL;
	if(pbuf == NULL || pkey == NULL)
	{
		return ERROR;
	}
	memset(pret,0,BUF_LINE_MAX_LEN);
	snprintf(ptmp_buff,BUF_LINE_MAX_LEN,"\"%s\":",pkey);
	ptmp = strstr(pbuf,ptmp_buff);
	if(ptmp == NULL)
	{
		return ERROR;
	}
	ptmp += strlen(ptmp_buff);
	if(ptmp[0] == '\"')
	{
		ptmp++;
		pend = strchr(ptmp,'\"');
		if(pend == NULL)
		{
			return ERROR;
		}
		if(pend == ptmp)
		{
			strcpy(pret,"NULL");
		}
		else
		{
			strncpy(pret,ptmp,pend-ptmp);
		}
	}
	else
	{
		pend = strchr(ptmp,',');
		if(pend == NULL)
		{
			return ERROR;
		}
		if(pend == ptmp)
		{
			strcpy(pret,"NULL");
		}
		else
		{
			strncpy(pret,ptmp,pend-ptmp);
		}
	}
	return OK;
}
int strtotime(char* datetime)
{  
	struct tm tm_time;  
	int unixtime;  
	strptime(datetime,"%Y-%m-%d %H:%M:%S",&tm_time);  
	  
	unixtime = mktime(&tm_time);  
	return unixtime;  
}
/**********************************************************************************
  Function:      qlv_put_params_string
  Description:  字符串的url编码
  Calls:
  Called By:
  Input:         char* str
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int qlv_put_params_string(char* string,char* key,char* value,int appendflag)
{
    if(appendflag == TRUE)
    {
        strcat(string,"&");
    }
    strcat(string,key);
    strcat(string,"=");
    if(value != NULL)
    {
        strcat(string,value);
    }
    return OK;
}
/**********************************************************************************
  Function:      qlv_get_md5sign
  Description:  字符串的url编码
  Calls:
  Called By:
  Input:         char* str
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int qlv_get_md5sign(char* src_string,char* out_sign)
{
    char tmp_string[ENCODEBUF_LINE_MAX_LEN] = {0};
    strcpy(tmp_string,src_string);
    strcat(tmp_string,QLV_MD5_KEYWORD);
	strcpy(out_sign,md5_hash((unsigned char *)tmp_string, strlen((const char *)tmp_string)));
    return OK;
}
#include "qrencode.h"                                     
#include <png.h>
enum imageType {
	PNG_TYPE,
	PNG32_TYPE,
	EPS_TYPE,
	SVG_TYPE,
	XPM_TYPE,
	ANSI_TYPE,
	ANSI256_TYPE,
	ASCII_TYPE,
	ASCIIi_TYPE,
	UTF8_TYPE,
	ANSIUTF8_TYPE,
	ANSI256UTF8_TYPE,
	UTF8i_TYPE,
	ANSIUTF8i_TYPE
};
#define INCHES_PER_METER (100.0/2.54)
static void fillRow(unsigned char *row, int num, const unsigned char color[])
{
	int i;

	for(i = 0; i < num; i++) {
		memcpy(row, color, 4);
		row += 4;
	}
}
static int writePNG(const QRcode *qrcode, const char *outfile, enum imageType type)
{
    static unsigned char fg_color[4] = {0, 0, 0, 255};
    static unsigned char bg_color[4] = {255, 255, 255, 255};
    int size = 3;
    int margin = 4;
    int dpi = 72;
    static FILE *fp; // avoid clobbering by setjmp.
	png_structp png_ptr;
	png_infop info_ptr;
	png_colorp palette = NULL;
	png_byte alpha_values[2];
	unsigned char *row, *p, *q;
	int x, y, xx, yy, bit;
	int realwidth;

	realwidth = (qrcode->width + margin * 2) * size;
	if(type == PNG_TYPE) {
		row = (unsigned char *)malloc((size_t)((realwidth + 7) / 8));
	} else if(type == PNG32_TYPE) {
		row = (unsigned char *)malloc((size_t)realwidth * 4);
	} else {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Internal error.");
        return ERROR;
	}
	if(row == NULL) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Failed to allocate memory.");
        return ERROR;
	}

	if(outfile[0] == '-' && outfile[1] == '\0') {
		fp = stdout;
	} else {
		fp = fopen(outfile, "wb");
		if(fp == NULL) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Failed to create file: %s", outfile);
			perror(NULL);
			return ERROR;
		}
	}

	png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if(png_ptr == NULL) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Failed to initialize PNG writer.");
        return ERROR;
	}

	info_ptr = png_create_info_struct(png_ptr);
	if(info_ptr == NULL) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Failed to initialize PNG write.");
        return ERROR;
	}

	if(setjmp(png_jmpbuf(png_ptr))) {
		png_destroy_write_struct(&png_ptr, &info_ptr);
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Failed to write PNG image.");
        return ERROR;
	}

	if(type == PNG_TYPE) {
		palette = (png_colorp) malloc(sizeof(png_color) * 2);
		if(palette == NULL) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Failed to allocate memory");
			return ERROR;
		}
		palette[0].red   = fg_color[0];
		palette[0].green = fg_color[1];
		palette[0].blue  = fg_color[2];
		palette[1].red   = bg_color[0];
		palette[1].green = bg_color[1];
		palette[1].blue  = bg_color[2];
		alpha_values[0] = fg_color[3];
		alpha_values[1] = bg_color[3];
		png_set_PLTE(png_ptr, info_ptr, palette, 2);
		png_set_tRNS(png_ptr, info_ptr, alpha_values, 2, NULL);
	}

	png_init_io(png_ptr, fp);
	if(type == PNG_TYPE) {
		png_set_IHDR(png_ptr, info_ptr,
				(unsigned int)realwidth, (unsigned int)realwidth,
				1,
				PNG_COLOR_TYPE_PALETTE,
				PNG_INTERLACE_NONE,
				PNG_COMPRESSION_TYPE_DEFAULT,
				PNG_FILTER_TYPE_DEFAULT);
	} else {
		png_set_IHDR(png_ptr, info_ptr,
				(unsigned int)realwidth, (unsigned int)realwidth,
				8,
				PNG_COLOR_TYPE_RGB_ALPHA,
				PNG_INTERLACE_NONE,
				PNG_COMPRESSION_TYPE_DEFAULT,
				PNG_FILTER_TYPE_DEFAULT);
	}
	png_set_pHYs(png_ptr, info_ptr,
			dpi * INCHES_PER_METER,
			dpi * INCHES_PER_METER,
			PNG_RESOLUTION_METER);
	png_write_info(png_ptr, info_ptr);

	if(type == PNG_TYPE) {
	/* top margin */
		memset(row, 0xff, (size_t)((realwidth + 7) / 8));
		for(y = 0; y < margin * size; y++) {
			png_write_row(png_ptr, row);
		}

		/* data */
		p = qrcode->data;
		for(y = 0; y < qrcode->width; y++) {
			memset(row, 0xff, (size_t)((realwidth + 7) / 8));
			q = row;
			q += margin * size / 8;
			bit = 7 - (margin * size % 8);
			for(x = 0; x < qrcode->width; x++) {
				for(xx = 0; xx < size; xx++) {
					*q ^= (*p & 1) << bit;
					bit--;
					if(bit < 0) {
						q++;
						bit = 7;
					}
				}
				p++;
			}
			for(yy = 0; yy < size; yy++) {
				png_write_row(png_ptr, row);
			}
		}
		/* bottom margin */
		memset(row, 0xff, (size_t)((realwidth + 7) / 8));
		for(y = 0; y < margin * size; y++) {
			png_write_row(png_ptr, row);
		}
	} else {
	/* top margin */
		fillRow(row, realwidth, bg_color);
		for(y = 0; y < margin * size; y++) {
			png_write_row(png_ptr, row);
		}

		/* data */
		p = qrcode->data;
		for(y = 0; y < qrcode->width; y++) {
			fillRow(row, realwidth, bg_color);
			for(x = 0; x < qrcode->width; x++) {
				for(xx = 0; xx < size; xx++) {
					if(*p & 1) {
						memcpy(&row[((margin + x) * size + xx) * 4], fg_color, 4);
					}
				}
				p++;
			}
			for(yy = 0; yy < size; yy++) {
				png_write_row(png_ptr, row);
			}
		}
		/* bottom margin */
		fillRow(row, realwidth, bg_color);
		for(y = 0; y < margin * size; y++) {
			png_write_row(png_ptr, row);
		}
	}

	png_write_end(png_ptr, info_ptr);
	png_destroy_write_struct(&png_ptr, &info_ptr);

	fclose(fp);
	free(row);
	free(palette);
	return 0;
}
static FILE *openFile(const char *outfile)
{
	FILE *fp;

	if(outfile == NULL || (outfile[0] == '-' && outfile[1] == '\0')) {
		fp = stdout;
	} else {
		fp = fopen(outfile, "wb");
		if(fp == NULL) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Failed to create file: %s", outfile);
			perror(NULL);
			return NULL;
		}
	}

	return fp;
}

static void writeUTF8_margin(FILE* fp, int realwidth, const char* white,
                             const char *reset, const char* full,int margin)
{
	int x, y;

	for (y = 0; y < margin/2; y++) {
		fputs(white, fp);
		for (x = 0; x < realwidth; x++)
			fputs(full, fp);
		fputs(reset, fp);
		fputc('\n', fp);
	}
}

static int writeUTF8(const QRcode *qrcode, const char *outfile, int use_ansi, int invert)
{
	FILE *fp;
	int x, y;
	int realwidth;
	const char *white, *reset;
	const char *empty, *lowhalf, *uphalf, *full;
    int margin = 2;

	empty = " ";
	lowhalf = "\342\226\204";
	uphalf = "\342\226\200";
	full = "\342\226\210";

	if (invert) {
		const char *tmp;

		tmp = empty;
		empty = full;
		full = tmp;

		tmp = lowhalf;
		lowhalf = uphalf;
		uphalf = tmp;
	}

	if (use_ansi){
		if (use_ansi == 2) {
			white = "\033[38;5;231m\033[48;5;16m";
		} else {
			white = "\033[40;37;1m";
		}
		reset = "\033[0m";
	} else {
		white = "";
		reset = "";
	}

	fp = openFile(outfile);

	realwidth = (qrcode->width + margin * 2);

	/* top margin */
	writeUTF8_margin(fp, realwidth, white, reset, full,margin);

	/* data */
	for(y = 0; y < qrcode->width; y += 2) {
		unsigned char *row1, *row2;
		row1 = qrcode->data + y*qrcode->width;
		row2 = row1 + qrcode->width;

		fputs(white, fp);

		for (x = 0; x < margin; x++) {
			fputs(full, fp);
		}

		for (x = 0; x < qrcode->width; x++) {
			if(row1[x] & 1) {
				if(y < qrcode->width - 1 && row2[x] & 1) {
					fputs(empty, fp);
				} else {
					fputs(lowhalf, fp);
				}
			} else if(y < qrcode->width - 1 && row2[x] & 1) {
				fputs(uphalf, fp);
			} else {
				fputs(full, fp);
			}
		}

		for (x = 0; x < margin; x++)
			fputs(full, fp);

		fputs(reset, fp);
		fputc('\n', fp);
	}

	/* bottom margin */
	writeUTF8_margin(fp, realwidth, white, reset, full,margin);
	fclose(fp);
	return 0;
}

/**********************************************************************************
  Function:      qlv_qrcode_create_png
  Description:  生成对应二维码文件
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
int qlv_qrcode_create_png(char* src_string,char* dst_filename)
{
    int qrversion=1;
    QRcode* pQRC = NULL;
    if(src_string == NULL || dst_filename == NULL)
    {
        return ERROR;
    }
    pQRC = QRcode_encodeString(src_string, qrversion, QR_ECLEVEL_H, QR_MODE_8, 1);
    if (pQRC == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"qlv_qrcode_create_png get pQRC FAILED");
        return ERROR;
    }
    
    writePNG(pQRC, dst_filename, PNG_TYPE);
    QRcode_free(pQRC);
    return OK;
}

/**********************************************************************************
  Function:      qlv_qrcode_create_utf8
  Description:  生成对应二维码文件
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
int qlv_qrcode_create_utf8(char* src_string,char* dst_filename)
{
    int qrversion=1;
    QRcode* pQRC = NULL;
    if(src_string == NULL)
    {
        return ERROR;
    }
    pQRC = QRcode_encodeString(src_string, qrversion, QR_ECLEVEL_H, QR_MODE_8, 1);
    if (pQRC == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"qlv_qrcode_create_utf8 get pQRC FAILED");
        return ERROR;
    }
    
    writeUTF8(pQRC, dst_filename,0, 0);
    QRcode_free(pQRC);
    return OK;
}

