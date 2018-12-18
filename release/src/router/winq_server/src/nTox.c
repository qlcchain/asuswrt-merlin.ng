/*
 * Textual frontend for Tox.
 */

/*
 * Copyright 漏 2016-2017 The TokTok team.
 * Copyright 漏 2013 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <pthread.h>  

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

#include "nTox.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*(x))
#endif

FriendStatusChange friendstatuschage;
SelfStatusChange selfstatuschange;
MessageProcess messageprocess;
FileProcess fileprocess;
GroupChatMessageProcess groupchatmessageprocess;
SendGroupNum sendgroupnum;
GetJson getjson;
GetPath getpath;

#define NTOX_DEBUG_PRINT
#define IP_MAX_SIZE 45
#define STRING_LENGTH_WRAPPED (STRING_LENGTH + 16 * (wrap_cont_len + 1))
#define SERVER_VERSION  1

static const char *data_file_name = NULL;
static const char *pass_data_file = NULL;
static const char *password_file_name = "password";
static char *requstWifiJSON = "ReqestWifPassword";
static char *AnswerWifiJSON = "ResponseWIFIPassword";
static char *AnswerNoSavePassJSON = "NoSavedPassword";

char assetInfo[40960] = {0};
Tox *qlinkNode = NULL;
wifiNodeInfo *wifiNodeInfo_H = NULL;
wifiNodeInfo *wifiNodeInfo_C = NULL;
int savedWifiNum = 0;
char dataPathFile[200] = {0};
char passdataPathFile[200] = {0};
char recv_filename[200] = {0};
int recv_filesize=0;
int g_tox_msgid = 0;
struct list_head g_tox_msg_send_list = LIST_HEAD_INIT(g_tox_msg_send_list);
pthread_rwlock_t g_tox_msg_send_lock = PTHREAD_RWLOCK_INITIALIZER;
static uint8_t num_requests = 0;
static File_Sender file_senders[NUM_FILE_SENDERS];
static uint8_t numfilesenders;
static int fmtmsg_tm_mday = -1;
extern char g_vpn_file_dir[VPN_FILE_DIR_MAX_LEN + 1];
extern int qrcode_show(void);
int g_tox_stop = 1;

static void tox_file_chunk_request(Tox *tox, uint32_t friend_number, uint32_t file_number, 
	uint64_t position, size_t length, void *user_data)
{
    unsigned int i;

    for (i = 0; i < NUM_FILE_SENDERS; ++i) {
        /* This is slow */
        if (file_senders[i].file && file_senders[i].friendnum == friend_number && file_senders[i].filenumber == file_number) {
            if (length == 0) {
                fclose(file_senders[i].file);
                file_senders[i].file = 0;
                char msg[512];
                sprintf(msg, "[t] %u file transfer: %u completed", file_senders[i].friendnum, file_senders[i].filenumber);
                //new_lines(msg);
                break;
            }

            fseek(file_senders[i].file, position, SEEK_SET);
            VLA(uint8_t, data, length);
            int len = fread(data, 1, length, file_senders[i].file);
            tox_file_send_chunk(tox, friend_number, file_number, position, data, len, 0);
            break;
        }
    }
}

static void frpuk_to_str(uint8_t *id_bin, char *id_str)
{
    uint32_t i, delta = 0, pos_extra = 0, sum_extra = 0;

    for (i = 0; i < TOX_PUBLIC_KEY_SIZE; i++) {
        sprintf(&id_str[2 * i + delta], "%02hhX", id_bin[i]);

        if ((i + 1) == TOX_PUBLIC_KEY_SIZE) {
            pos_extra = 2 * (i + 1) + delta;
        }

        if (i >= TOX_PUBLIC_KEY_SIZE) {
            sum_extra |= id_bin[i];
        }

/*
        if (!((i + 1) % FRADDR_TOSTR_CHUNK_LEN)) {
            id_str[2 * (i + 1) + delta] = ' ';
            delta++;
        }
        */
    }

    id_str[2 * i + delta] = 0;

    if (!sum_extra) {
        id_str[pos_extra] = 0;
    }
}

static void fraddr_to_str(uint8_t *id_bin, char *id_str)
{
    uint32_t i, delta = 0, pos_extra = 0, sum_extra = 0;

    for (i = 0; i < TOX_ADDRESS_SIZE; i++) {
        sprintf(&id_str[2 * i + delta], "%02hhX", id_bin[i]);

        if ((i + 1) == TOX_PUBLIC_KEY_SIZE) {
            pos_extra = 2 * (i + 1) + delta;
        }

        if (i >= TOX_PUBLIC_KEY_SIZE) {
            sum_extra |= id_bin[i];
        }

/*
        if (!((i + 1) % FRADDR_TOSTR_CHUNK_LEN)) {
            id_str[2 * (i + 1) + delta] = ' ';
            delta++;
        }
        */
    }

    id_str[2 * i + delta] = 0;

    if (!sum_extra) {
        id_str[pos_extra] = 0;
    }
}

static void get_id(Tox *m, char *data)
{
   // sprintf(data, "[i] ID: ");
    //int offset = strlen(data);
    
    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(m, address);
    fraddr_to_str(address, data);
	
}

static int getfriendname_terminated(Tox *m, int friendnum, char *namebuf)
{
    tox_friend_get_name(m, friendnum, (uint8_t *)namebuf, NULL);
    int res = tox_friend_get_name_size(m, friendnum, NULL);

    if (res >= 0) {
        namebuf[res] = 0;
    } else {
        namebuf[0] = 0;
    }

    return res;
}

int map_msg ( char* type )
{
	if ( strcmp ( checkConnectReq,type ) ==0 )
	{
		return TYPE_CheckConnectReq;
	}
	else if ( strcmp ( sendVpnFileRequest,type ) ==0 )
	{
		return TYPE_SendVpnFileRequest;
	}
	else if ( strcmp ( vpnUserPassAndPrivateKeyReq,type ) ==0 )
	{
		return TYPE_VpnUserPassAndPrivateKeyReq;
	}
	else if ( strcmp ( vpnUserPassAndPrivateKeyRsp,type ) ==0 )
	{
		return TYPE_VpnUserPassAndPrivateKeyRsp;
	}
	else if ( strcmp ( vpnUserAndPasswordReq,type ) ==0 )
	{
		return TYPE_VpnUserAndPasswordReq;
	}
	else if ( strcmp ( vpnUserAndPasswordRsp,type ) ==0 )
	{
		return TYPE_VpnUserAndPasswordRsp;
	}
	else if ( strcmp ( vpnPrivateKeyReq,type ) ==0 )
	{
		return TYPE_VpnPrivateKeyReq;
	}
	else if ( strcmp ( vpnPrivateKeyRsp,type ) ==0 )
	{
		return TYPE_VpnPrivateKeyRsp;
	}
	else if ( strcmp ( joinGroupChatReq,type ) ==0 )
	{
		return TYPE_JoinGroupChatReq;
	}
	else if ( strcmp ( recordSaveReq,type ) ==0 )
	{
		return TYPE_RecordSaveReq;
	}
    else if ( strcmp ( sendVpnFileListReq,type ) ==0 )
	{
		return TYPE_SendVpnFileListReq;
	}
    else if ( strcmp ( sendVpnFileListRsp,type ) ==0 )
	{
		return TYPE_SendVpnFileListRsp;
	}
    else if ( strcmp ( sendVpnFileNewReq,type ) ==0 )
	{
		return TYPE_SendVpnFileNewReq;
	}
    else if ( strcmp ( sendVpnFileNewRsp,type ) ==0 )
	{
		return TYPE_SendVpnFileNewRsp;
	}
    else if ( strcmp ( vpnRegisterSuccessNotify,type ) ==0 )
	{
		return TYPE_VpnRegisterSuccessNotify;
	}
	else
	{
		return TYPE_UNKNOW;
	}
}

int friend_Message_process(Tox *m,int friendnum,char *message)
{
	char type[32];

	if(NULL == message)
	{
		return -1;
	}
	cJSON * pJson = cJSON_Parse(message);
	if(NULL == pJson)																						  
	{
		// parse faild, return
	  return -2;
	}

	// get string from json
	cJSON * pSub = cJSON_GetObjectItem(pJson, "type");
	if(NULL == pSub)
	{
		return -3;
	}
	//printf("type : %s\n", pSub->valuestring);
	strcpy(type,pSub->valuestring);

    DEBUG_PRINT(DEBUG_LEVEL_INFO,"friend_Message_process:get msg(%s-%s)",type, message);
    switch ( map_msg ( type ) )
	{
		case TYPE_CheckConnectReq:
			processCheckConnectReq ( pJson,friendnum );
			break;
		case TYPE_SendVpnFileRequest:
			processSendVpnFileRequest ( pJson, friendnum );
			break;
		case TYPE_VpnUserPassAndPrivateKeyReq:
			processVpnUserPassAndPrivateKeyReq ( pJson,friendnum );
			break;
		case TYPE_VpnUserPassAndPrivateKeyRsp:
			processVpnUserPassAndPrivateKeyRsp ( pJson,friendnum );
			break;
		case TYPE_VpnUserAndPasswordReq:
			processVpnUserAndPasswordReq ( pJson,friendnum );
			break;
		case TYPE_VpnUserAndPasswordRsp:
			processVpnUserAndPasswordRsp ( pJson,friendnum );
			break;
		case TYPE_VpnPrivateKeyReq:
			processVpnPrivateKeyReq ( pJson,friendnum );
			break;
		case TYPE_VpnPrivateKeyRsp:
			processVpnPrivateKeyRsp ( pJson,friendnum );
			break;
		case TYPE_JoinGroupChatReq:
			processJoinGroupChatReq ( pJson, friendnum );
			break;
		case TYPE_RecordSaveReq:
			processRecordSaveReq ( pJson,friendnum );
			break;
        case TYPE_SendVpnFileListReq:
			processSendVpnFileListReq ( pJson,friendnum );
			break;
        case TYPE_SendVpnFileListRsp:
			processSendVpnFileListRsp ( pJson,friendnum );
			break;
        case TYPE_SendVpnFileNewReq:
			processSendVpnFileNewReq ( pJson,friendnum );
			break;
        case TYPE_SendVpnFileNewRsp:
			processSendVpnFileNewRsp ( pJson,friendnum );
			break;
        case TYPE_VpnRegisterSuccessNotify:
			processVpnRegisterSuccessNotify ( pJson,friendnum );
			break;
		case TYPE_UNKNOW:
			DEBUG_PRINT(DEBUG_LEVEL_NORMAL,"UNKNOW Message(%s)",type);
			break;
		default:
			break;
	
    }

	cJSON_Delete(pJson);
	return 0;	
}

static void print_formatted_message(Tox *m, char *message, int friendnum, uint8_t outgoing)
{
    char name[TOX_MAX_NAME_LENGTH + 1];
    getfriendname_terminated(m, friendnum, name);

    VLA(char, msg, 100 + strlen(message) + strlen(name) + 1);
#ifdef NTOX_DEBUG_PRINT
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    /* assume that printing the date once a day is enough */
    if (fmtmsg_tm_mday != timeinfo->tm_mday) {
        fmtmsg_tm_mday = timeinfo->tm_mday;

		
        // strftime(msg, 100, "Today is %a %b %d %Y.", timeinfo); 
        /* %x is the locale's preferred date format */
        // strftime(msg, 100, "Today is %x.", timeinfo);
        strftime(msg,100,"Time:%Y-%m-%d %H:%M:%S",timeinfo);
        ////new_lines(msg);
    }

    char time[64];
     //strftime(time, 64, "%I:%M:%S %p", timeinfo); 
    /* %X is the locale's preferred time format */
   // strftime(time, 64, "%X", timeinfo);

	 strftime(time,64,"Time:%Y-%m-%d %H:%M:%S",timeinfo);

    if (outgoing) {
        /* tgt: friend */
        sprintf(msg, "[%d] %s =>{%s} %s", friendnum, time, name, message);
    } else {
        /* src: friend */
        sprintf(msg, "[%d] %s <%s>: %s", friendnum, time, name, message);
    }

   // //new_lines(msg);
#endif	    
	////new_lines(message);
	//printf("\n %s %s %s",name,time,message);

	uint8_t fraddr_bin[TOX_PUBLIC_KEY_SIZE];
	char fraddr_str[FRAPUKKEY_TOSTR_BUFSIZE]={0};
	if (tox_friend_get_public_key(qlinkNode, friendnum, fraddr_bin, NULL)) 
	 {
		frpuk_to_str(fraddr_bin, fraddr_str);
		DEBUG_PRINT(DEBUG_LEVEL_INFO,"friend public key is %s", fraddr_str);
	 }
	
	if(messageprocess!=NULL)
	{
		messageprocess(message,fraddr_str);
	}
	friend_Message_process(m,friendnum,message);
}

/* forward declarations */
static int save_data(Tox *m);

/*add by zhijie to auto accpet request, Begin*/
static void auto_accept_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    ////new_lines("[i] auto_accept_request received friend request with message:");
    ////new_lines((const char *)data);
    char numchar[150];
	uint8_t fraddr_bin[TOX_ADDRESS_SIZE];
    char fraddr_str[FRADDR_TOSTR_BUFSIZE];
    sprintf(numchar, "[i] auto_accept_request accept request with /a %u", num_requests);
   // //new_lines(numchar);
    {
        uint32_t num = tox_friend_add_norequest(m, public_key, NULL);
		 if (tox_friend_get_public_key(m, num, fraddr_bin, NULL)) 
		 {
            fraddr_to_str(fraddr_bin, fraddr_str);
		 }

        if (num != UINT32_MAX) {
            sprintf(numchar, "[i] friend request %s accepted as friend no. %d", fraddr_str, num);
            ////new_lines(numchar);
/*            if(m!=NULL)
            {
            	save_data(m);
            }*/
        } else {
            sprintf(numchar, "[i] failed to add friend");
           // //new_lines(numchar);
        }
    }
	//do_refresh();
}

/*add by zhijie to auto accpet request, End*/

static void print_message(Tox *m, uint32_t friendnumber, TOX_MESSAGE_TYPE type, const uint8_t *string, size_t length,
                          void *userdata)
{
    /* ensure null termination */
    VLA(uint8_t, null_string, length + 1);
    memcpy(null_string, string, length);
    null_string[length] = 0;
    print_formatted_message(m, (char *)null_string, friendnumber, 0);
}

static void print_statuschange(Tox *m, uint32_t friendnumber, const uint8_t *string, size_t length, void *userdata)
{
    char name[TOX_MAX_NAME_LENGTH + 1];

    if (getfriendname_terminated(m, friendnumber, name) != -1) {
        VLA(char, msg, 100 + length + strlen(name) + 1);

        if (name[0] != 0) {
            sprintf(msg, "[i] [%d] %s's status changed to %s.", friendnumber, name, string);
        } else {
            sprintf(msg, "[i] [%d] Their status changed to %s.", friendnumber, string);
        }

        ////new_lines(msg);
    }
}






static Tox *load_data(void)
{
    FILE *data_file = fopen(data_file_name, "r");

    if (data_file) {
        fseek(data_file, 0, SEEK_END);
        size_t size = ftell(data_file);
        rewind(data_file);

        VLA(uint8_t, data, size);

        if (fread(data, sizeof(uint8_t), size, data_file) != size) {
            //fputs("[!] could not read data file!\n", stderr);
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"[!] could not read data file!");
            fclose(data_file);
            return 0;
        }
        struct Tox_Options options;

        tox_options_default(&options);
		//add by zhijie, disable local discovery,Begin

		//tox_options_set_local_discovery_enabled(&options, false);

		//add by zhijie, disable local discovery,end
		

		/*Zhijie, add to enable the TCP_relay Begin*/
		//tox_options_set_tcp_port(&options,49734);
		/*Zhijie, add to enable the TCP_relay End*/

        options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;

        options.savedata_data = data;

        options.savedata_length = size;
        Tox *m = tox_new(&options, NULL);

        if (fclose(data_file) < 0) {
            perror("[!] fclose failed");
            /* we got it open and the expected data read... let it be ok */
            /* return 0; */
        }

        return m;
    }
    return tox_new(NULL, NULL);
}

static int save_data(Tox *m)
{
    FILE *data_file = fopen(data_file_name, "w");

    if (!data_file) {
        perror("[!] load_key");
        return 0;
    }

    int res = 1;
    size_t size = tox_get_savedata_size(m);
    VLA(uint8_t, data, size);
    tox_get_savedata(m, data);

    if (fwrite(data, sizeof(uint8_t), size, data_file) != size) {
        fputs("[!] could not write data file (1)!", stderr);
        res = 0;
    }

    if (fclose(data_file) < 0) {
        perror("[!] could not write data file (2)");
        res = 0;
    }

    return res;
}

static int save_data_file(Tox *m, const char *path)
{
    data_file_name = path;

    if (save_data(m)) {
        return 1;
    }

    return 0;
}

static void print_invite(Tox *m, uint32_t friendnumber, TOX_CONFERENCE_TYPE type, const uint8_t *data, size_t length,
                         void *userdata)
{
    char msg[256];

    if (type == TOX_CONFERENCE_TYPE_TEXT) {
	// printf("[i] received group chat invite from: %u, auto accepting and joining. group number: %u\n", friendnumber,
      //          tox_conference_join(m, friendnumber, data, length, NULL));
      //  sprintf(msg, "[i] received group chat invite from: %u, auto accepting and joining. group number: %u", friendnumber,
      //          tox_conference_join(m, friendnumber, data, length, NULL));
		int groupnum= tox_conference_join(m, friendnumber, data, length, NULL);
	if(sendgroupnum!=NULL)
	{
		sendgroupnum(groupnum);
	}
    } else {
        sprintf(msg, "[i] Group chat invite received of type %u that could not be accepted by ntox.", type);
    }

    //new_lines(msg);
}

static void print_groupchatpeers(Tox *m, int groupnumber)
{
    uint32_t num = tox_conference_peer_count(m, groupnumber, NULL);
    if (num == UINT32_MAX) {
        return;
    }

    if (!num) {
        //new_lines("[g]+ no peers left in group.");
        return;
    }

    typedef uint8_t Peer_Name[TOX_MAX_NAME_LENGTH];
    VLA(Peer_Name, names, num);
    VLA(size_t, lengths, num);

    uint32_t i;

    for (i = 0; i < num; ++i) {
        lengths[i] = tox_conference_peer_get_name_size(m, groupnumber, i, NULL);
        tox_conference_peer_get_name(m, groupnumber, i, names[i], NULL);
    }

    char numstr[16];
    char header[] = "[g]+ ";
    size_t header_len = strlen(header);
    char msg[STRING_LENGTH];
    strcpy(msg, header);
    size_t len_total = header_len;

    for (i = 0; i < num; ++i) {
        size_t len_name = lengths[i];
        size_t len_num = sprintf(numstr, "%i: ", i);

        if (len_num + len_name + len_total + 3 >= STRING_LENGTH) {
            //new_lines_mark(msg, 1);

            strcpy(msg, header);
            len_total = header_len;
        }

        strcpy(msg + len_total, numstr);
        len_total += len_num;
        memcpy(msg + len_total, (char *)names[i], len_name);
        len_total += len_name;

        if (i < num - 1) {
            strcpy(msg + len_total, "|");
            len_total++;
        }
    }

    //new_lines_mark(msg, 1);
}

static void print_groupmessage(Tox *m, uint32_t groupnumber, uint32_t peernumber, TOX_MESSAGE_TYPE type,
                               const uint8_t *message, size_t length,
                               void *userdata)
{
	//Call_Log_To_Java(message);
    VLA(char, msg, 256 + length);

    TOX_ERR_CONFERENCE_PEER_QUERY error;
    size_t len = tox_conference_peer_get_name_size(m, groupnumber, peernumber, &error);
    uint8_t name[TOX_MAX_NAME_LENGTH] = {0};
    tox_conference_peer_get_name(m, groupnumber, peernumber, name, NULL);

    //print_groupchatpeers(m, groupnumber);
    if (len == 0 || error != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
        name[0] = 0;
    }

    if (name[0] != 0) {
        sprintf(msg, "[g] %u: %u <%s>: %s", groupnumber, peernumber, name, message);
    } else {
        sprintf(msg, "[g] #%u: %u Unknown: %s", groupnumber, peernumber, message);
    }
	if(groupchatmessageprocess!=NULL)
	{
		groupchatmessageprocess((char *)name,message,groupnumber);
	}

    //new_lines(msg);
}
static void print_groupnamelistchange(Tox *m, uint32_t groupnumber, uint32_t peernumber,
                                      TOX_CONFERENCE_STATE_CHANGE change,
                                      void *userdata)
{
    char msg[256];

    if (change == TOX_CONFERENCE_STATE_CHANGE_PEER_JOIN) {
        sprintf(msg, "[g] #%i: New peer %i.", groupnumber, peernumber);
        //new_lines(msg);
    } else if (change == TOX_CONFERENCE_STATE_CHANGE_PEER_EXIT) {
        /* if peer was the last in list, it simply dropped,
         * otherwise it was overwritten by the last peer
         *
         * adjust output
         */
        uint32_t peers_total = tox_conference_peer_count(m, groupnumber, NULL);

        if (peers_total == peernumber) {
            sprintf(msg, "[g] #%i: Peer %i left.", groupnumber, peernumber);
            //new_lines(msg);
        } else {
            TOX_ERR_CONFERENCE_PEER_QUERY error;
            uint8_t peername[TOX_MAX_NAME_LENGTH] = {0};
            size_t len = tox_conference_peer_get_name_size(m, groupnumber, peernumber, &error);
            tox_conference_peer_get_name(m, groupnumber, peernumber, peername, NULL);

            if (len == 0 || error != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
                peername[0] = 0;
            }

            sprintf(msg, "[g] #%i: Peer %i left. Former peer [%i: <%s>] is now peer %i.", groupnumber, peernumber,
                    peers_total, peername, peernumber);
            //new_lines(msg);
        }
    } else if (change == TOX_CONFERENCE_STATE_CHANGE_PEER_NAME_CHANGE) {
        uint8_t peername[TOX_MAX_NAME_LENGTH] = {0};
        int len = tox_conference_peer_get_name_size(m, groupnumber, peernumber, NULL);
        tox_conference_peer_get_name(m, groupnumber, peernumber, peername, NULL);

        if (len <= 0) {
            peername[0] = 0;
        }

        sprintf(msg, "[g] #%i: Peer %i's name changed: %s", groupnumber, peernumber, peername);
        //new_lines(msg);
    } else {
        sprintf(msg, "[g] #%i: Name list changed (peer %i, change %i?):", groupnumber, peernumber, change);
        //new_lines(msg);
        print_groupchatpeers(m, groupnumber);
    }
}

static void file_request_accept(Tox *tox, uint32_t friend_number, uint32_t file_number, uint32_t type,
                                uint64_t file_size,
                                const uint8_t *filename, size_t filename_length, void *user_data)
{
	if(filename!=NULL)
	{
		if(getpath!=NULL)
		{
			memset(recv_filename,0x00,200);
			char *filepath=getpath(filename);
			if((filepath!=NULL)||(strlen(filepath)==0))
				strcpy(recv_filename,filepath);
		}
	}
	recv_filesize = (int)file_size;
    if (type != TOX_FILE_KIND_DATA) {
        //new_lines("Refused invalid file type.");
        printf("Refused invalid file type.\n");
        tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, 0);
        return;
    }

   // sprintf(msg, "[t] %u is sending us: %s of size %llu", friend_number, filename, (long long unsigned int)file_size);
   printf("friend_number: %u is sending us: %s of size %llu\n", friend_number, filename, (long long unsigned int)file_size);
    //new_lines(msg);

    if (tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_RESUME, 0)) {
      //  sprintf(msg, "Accepted file transfer. (saving file as: %u.%u.bin)", friend_number, file_number);
        // printf("Accepted file transfer. (saving file as: %s)\n", recv_filename);
        //new_lines(msg);
    } else {
        //new_lines("Could not accept file transfer.");
        printf("Could not accept file transfer.");
    }
}

static void file_print_control(Tox *tox, uint32_t friend_number, uint32_t file_number, TOX_FILE_CONTROL control,
                               void *user_data)
{
    if (control == TOX_FILE_CONTROL_CANCEL) {
        unsigned int i;

        for (i = 0; i < NUM_FILE_SENDERS; ++i) {
            /* This is slow */
            if (file_senders[i].file && file_senders[i].friendnum == friend_number && file_senders[i].filenumber == file_number) {
                fclose(file_senders[i].file);
                file_senders[i].file = 0;
            }
        }
    }
}

static void write_file(Tox *tox, uint32_t friendnumber, uint32_t filenumber, uint64_t position, const uint8_t *data,
                       size_t length, void *user_data)
{
    if (length == 0) {
        printf("file %s transfer from friendnumber %u completed\n" ,recv_filename, friendnumber);
		if(fileprocess!=NULL)
		{
			
			uint8_t fraddr_bin[TOX_PUBLIC_KEY_SIZE];
			char fraddr_str[FRAPUKKEY_TOSTR_BUFSIZE]={0};
			if (tox_friend_get_public_key(qlinkNode, friendnumber, fraddr_bin, NULL)) 
			{
				frpuk_to_str(fraddr_bin, fraddr_str);
				printf("friend public key is %s\n", fraddr_str);
			}
			else
				return;
			
			fileprocess(recv_filename, recv_filesize,fraddr_str);
		}
        return;
    }
	if((recv_filename!=NULL)&&(strlen(recv_filename)!=0))
	{
		printf("recv_filename is %s\n",recv_filename);
   	 	FILE *pFile = fopen(recv_filename, "r+b");

    	if (pFile == NULL) {
        	pFile = fopen(recv_filename, "wb");
    	}

    	fseek(pFile, position, SEEK_SET);

   		if (fwrite(data, length, 1, pFile) != 1) {
       		 printf("Error writing to file\n");
    	}
    	fclose(pFile);
	}
	else
    {   
		printf("recv_filename hava no value\n");
    }
}

static void print_online(Tox *tox, uint32_t friendnumber, TOX_CONNECTION status, void *userdata)
{

	char name[TOX_MAX_NAME_LENGTH + 1];
	char msg[512];
	if (getfriendname_terminated(tox, friendnumber, name) != -1) 
	{
		 if (status) 
	 	{
	 		sprintf(msg, "[i] [%d] friend with name %s went online.", friendnumber, name);
			
	    } else 
	    {
	        sprintf(msg, "[i] [%d] friend with name %s  went offline.", friendnumber, name);
				
		}
	}
	else
	{
	 	if (status) 
		{
	        sprintf(msg,"[i] [%d] friend with no name went online.", friendnumber);
	    } 
		else 
		{
		    sprintf(msg,"[i] [%d] friend with no name went offline.", friendnumber);
		}			
	}

	DEBUG_PRINT(DEBUG_LEVEL_INFO, "%s", msg);

	uint8_t fraddr_bin[TOX_PUBLIC_KEY_SIZE];
	char fraddr_str[FRAPUKKEY_TOSTR_BUFSIZE]={0};
	if (tox_friend_get_public_key(qlinkNode, friendnumber, fraddr_bin, NULL)) 
 	{
		frpuk_to_str(fraddr_bin, fraddr_str);
		DEBUG_PRINT(DEBUG_LEVEL_INFO, "friend public key is %s\n", fraddr_str);
 	}
	else
		return;

	
	if(friendstatuschage!=NULL)
	{
		friendstatuschage(fraddr_str,status);
	}
}

//static unsigned int connected_t1;
static void tox_connection_status(Tox *tox, TOX_CONNECTION connection_status, void *user_data)
{
 
    if (connection_status) {
        DEBUG_PRINT(DEBUG_LEVEL_INFO, "[i] You went Online");
    } else {
		DEBUG_PRINT(DEBUG_LEVEL_INFO, "[i] You went Offline");
    }
	
	if(selfstatuschange!=NULL)
	{
   		selfstatuschange(connection_status);
	}
}
void  print_msg(char *ptr)
{
	int retval;
	int id=pthread_self();
	printf("Thread 1 ID: %x\n",id);
	  printf("%s",ptr);
	pthread_exit(&retval);
}


char  homeDirPath[100] = {QLV_TOPDIR};
/* Java_com_stratagile_qlink_qlinkcom_CreatedP2PNetwork()
** This is the entry of the p2p function, androip app must call it firstly to use the p2p.
** The function will run with while(1) loop to complete the p2p function, so it is needed to open a thread to run this function.
*/
int CreatedP2PNetwork(void)
{
    const char *filename = "data";
    char idstring[200] = {0};
    Tox *m = NULL;

    strcpy(dataPathFile,homeDirPath);
 
    ///data_file_name = filename;
    data_file_name = strcat(dataPathFile,filename);
	

	//char* passdataPath_p =  Jstring2CStr(env,passwordPath);	
	strcpy(passdataPathFile,homeDirPath);

	pass_data_file = strcat(passdataPathFile, password_file_name);
	//FILE *data_file = fopen(password_file_name, "w");
	//DEBUG_PRINT(DEBUG_LEVEL_INFO,"password file is %s",pass_data_file);
    m = load_data();
	qlinkNode = m;
    if (!m) {
		m=tox_new(NULL, NULL);
		qlinkNode = m;
        //fputs("Failed to allocate Messenger datastructure", stderr);
        //exit(0);
    }

    save_data_file(m, data_file_name);
	//DEBUG_PRINT(DEBUG_LEVEL_INFO,"save_data_file OK");
	if(qlinkNode != NULL)
	{
		int friendcounts=tox_self_get_friend_list_size(qlinkNode);
		if(friendcounts>0)
		{
			int i;
			for(i=0;i<friendcounts;i++)
			{
				int res = tox_friend_delete(qlinkNode, friendcounts-1-i, NULL);
			 	if (res) {
					printf("remove a friend success\n");
				//	save_data(qlinkNode);
			 	} else {
					printf("remove a friend fail\n");
					//return -2;
				}
			 	usleep(1000);
			}
			m=qlinkNode;
			save_data(qlinkNode);
			//return 0;
		}
	}
    
	readvpnAssetfile ();
	//DEBUG_PRINT(DEBUG_LEVEL_INFO,"assetinfo is %s",assetInfo );
	CreatedNewGroupChatForAsset();
	tox_callback_friend_request(m, auto_accept_request);
	tox_callback_friend_message(m, print_message);
    //tox_callback_friend_name(m, print_nickchange);
    tox_callback_friend_status_message(m, print_statuschange);
    tox_callback_friend_connection_status(m, print_online);
	tox_callback_self_connection_status(m, tox_connection_status);
	/*20180129,wenchao,add these callback to send file to friend or recv file from friend ,begin*/
	tox_callback_file_recv_chunk(m, write_file);
    tox_callback_file_recv_control(m, file_print_control);
    tox_callback_file_recv(m, file_request_accept);
    tox_callback_file_chunk_request(m, tox_file_chunk_request);
	/*20180129,wenchao,add these callback to send file to friend or recv file from friend ,end*/

	/*20180307,wenchao,add these callback to group chat ,begin*/
   	tox_callback_conference_invite(m, print_invite);
   	tox_callback_conference_message(m, print_groupmessage);
   	tox_callback_conference_namelist_change(m, print_groupnamelistchange);
	/*20180307,wenchao,add these callback to group chat ,end*/

    get_id(m, idstring);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "start tox");
	DEBUG_PRINT(DEBUG_LEVEL_INFO,"MY id is %s",idstring);
	if ( idstring !=NULL )
	{
		writep2pidtofile ( idstring );
		//create toxid png
        qlv_qrcode_create_png(idstring, QLV_TOXP2PID_PNGFILE);
	}
    
	/*20180124,wenchao,use Tox Bootstrap,Begin*/
	int nodeslist_ret = load_DHT_nodeslist();
	if (nodeslist_ret != 0) {
		DEBUG_PRINT(DEBUG_LEVEL_INFO,"DHT nodeslist failed to load");
	}

    const char *name = "QLV-Server";
    tox_self_set_name(m, (uint8_t *)name, strlen(name), NULL);    

    time_t timestamp0 = time(NULL);	
    int on = 0;
    while (!g_tox_stop) {
		do_tox_connection(m);
		if(1)
		{
            if (tox_self_get_connection_status(m))
			{
				if (on == 0)
				{
					DEBUG_PRINT(DEBUG_LEVEL_INFO,"[i] connected to DHT, check the name");
                    on = 1;
				}
            } 
			else 
			{
				if(on == 1)
				{
					on = 0;
					DEBUG_PRINT(DEBUG_LEVEL_INFO,"[i] Reconnecting to DHT");
				}

			
                time_t timestamp1 = time(NULL);
                if (timestamp0 + 10 < timestamp1) 
				{
                    timestamp0 = timestamp1;
                    do_tox_connection(m);
                }
            }
        }
        tox_iterate(m, NULL);
		usleep(tox_iteration_interval(m) * 1000);
    }

	tox_kill(m);
	qlinkNode = NULL;
	m = NULL;
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "stop tox");
	
	return 0;
}

/*check if we conncected to the p2p Network
** -1 if qlinkNode is not valid
** 0 not connect
** 1 connected to p2p network, TCP
** 2 connected to p2p network, UDP
** call this function and update app own connected state on UI
*/
int GetP2PConnectionStatus()
{
	if(qlinkNode != NULL)
	{
		return (tox_self_get_connection_status(qlinkNode));
		
	}
	else return -1;
	
}


/* End a p2p_network
** it shall be called when app quit or to stop the p2p network
*/
int EndP2PConnection()
{
	if(qlinkNode != NULL)
	{
		//const char *filename = "data";
		//save_data_file(qlinkNode, data_file_name);
	    tox_kill(qlinkNode);
		qlinkNode = NULL;
		return 0;
	}
	else
		return -1;
	
}


/* ReturnOwnP2PId
** call this function to get our own p2p ID,  p2p ID with lenth TOX_ADDRESS_SIZE (38 bytes)
** for example : 2EADC1764978270C0750374D1C1913226D84B41C652FE132AA8FBA3FEAC51D77C265812D4746
** but the parameter id is char *type, please make sure id with more than TOX_ADDRESS_SIZE*2 + 1 to save it
** when app got it own p2p id, call the blockchain sdk to save the SSID+MAC+P2PID+etc
** 0 got the ID
** -1 qlinkNode is not valid
** -2 if p2pid is not valid
*/

int ReturnOwnP2PId(char * myOwnp2pId)
{
	if(qlinkNode != NULL)
	{
		char p2pid[TOX_ADDRESS_SIZE*2 + 1];
		get_id(qlinkNode, p2pid);
		p2pid[TOX_ADDRESS_SIZE*2] = '\0';
		if (p2pid == NULL)
		{
			return -2;
		}
		if (p2pid != NULL)
		{
			memcpy(myOwnp2pId, p2pid, strlen(p2pid));
  //	CHECK_EXCEPTION 0;
			return 0;
		}
	}
			
	return -1;

}

/* AddFriend
** 
** the friend p2pid has the same strcture of its own p2pid, see the Java_com_stratagile_qlink_qlinkcom_ReturnOwnP2PId() for detail
** for example : 2EADC1764978270C0750374D1C1913226D84B41C652FE132AA8FBA3FEAC51D77C265812D4746
** After the app seached the local wifi, call the blockchain sdk with the parameters of wifi SSID+MAC and get the friend p2p ID
** Call this function to add p2p friend with the parameter of the friend p2pid
** And then the p2p function will try to monitor if it is ok to build a peer to peer connection with this friend
** 
** -1 qlinkNode is not valid
** -2 invalid friendid address
** num is this location of friend in friend list, for example, if this is the 1st friend, num is 0, 2nd friend, num is 1.
*/

int AddFriend(char * friendid_p)
{
	if(qlinkNode != NULL)
	{ // add friend command: /f ID
		if(friendid_p == NULL)
			return -2;

		int friendLoc=GetFriendNumInFriendlist(friendid_p);
		if (friendLoc >=0) 
		{
			int res = tox_friend_delete(qlinkNode, friendLoc, NULL);
	 		if (res) 
	 		{
				printf("remove a friend success\n");
	 		} 
			else 
			{
				printf("remove a friend fail\n");
			}
		}		

        unsigned char *bin_string = hex_string_to_bin(friendid_p);
        TOX_ERR_FRIEND_ADD error;
        uint32_t num = tox_friend_add(qlinkNode, bin_string, (const uint8_t *)"Hi WIFI friend", sizeof("Hi WIFI friend"), &error);
        free(bin_string);
        char numstring[100];

        switch (error) {
            case TOX_ERR_FRIEND_ADD_TOO_LONG:
                sprintf(numstring, "[i] Message is too long.");
                break;

            case TOX_ERR_FRIEND_ADD_NO_MESSAGE:
                sprintf(numstring, "[i] Please add a message to your request.");
                break;

            case TOX_ERR_FRIEND_ADD_OWN_KEY:
                sprintf(numstring, "[i] That appears to be your own ID.");
                break;

            case TOX_ERR_FRIEND_ADD_ALREADY_SENT:
                sprintf(numstring, "[i] Friend request already sent.");
                break;

            case TOX_ERR_FRIEND_ADD_BAD_CHECKSUM:
                sprintf(numstring, "[i] Address has a bad checksum.");
                break;

            case TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM:
                sprintf(numstring, "[i] New nospam set.");
                break;

            case TOX_ERR_FRIEND_ADD_MALLOC:
                sprintf(numstring, "[i] malloc error.");
                break;

            case TOX_ERR_FRIEND_ADD_NULL:
                sprintf(numstring, "[i] message was NULL.");
                break;

            case TOX_ERR_FRIEND_ADD_OK:
                sprintf(numstring, "[i] Added friend as %d.", num);
               // save_data(qlinkNode);
                break;
        }

        printf("%s",numstring);
		return num;
    }
	else 
		return -1;
}

/* GetNumOfFriends()
** return the num of added friends, the app may use it to list or copy the friend list 
** -1 qlinkNode is not valid
** >=0 friendnum
*/
int GetNumOfFriends()
{
	if(qlinkNode != NULL)
		return tox_self_get_friend_list_size(qlinkNode);
	else 
		return -1;
}


/* GetFriendP2PPublicKey
** 
** input the friendnum ( 0 ~ (friendnum-1)) and get the pubKey of the friend
** Pubkey 32 bytes long which is just the former 32 bytes of the friend p2p ID
** 0 get the pubkey 
** -1 qlinkNode is not valid
** -2 invalid  friend num
** -3 invalid p2pid address
*/
int GetFriendP2PPublicKey(char * p2pid, char * friendPubKey)
{
	
	if(qlinkNode != NULL)
	{
		if(p2pid==NULL)
			return -3;
		char friendPubKey_C[TOX_PUBLIC_KEY_SIZE*2 + 1];

		int friendNum=GetFriendNumInFriendlist(p2pid);
		
		if((friendNum < 0)||(friendNum >= tox_self_get_friend_list_size(qlinkNode)))
		{
			printf("Invalid friendNum %d\n", friendNum);
			return -2;
		}
		uint8_t fraddr_bin[TOX_PUBLIC_KEY_SIZE];
		char fraddr_str[FRAPUKKEY_TOSTR_BUFSIZE];
		if (tox_friend_get_public_key(qlinkNode, friendNum, fraddr_bin, NULL)) 
		 {
			frpuk_to_str(fraddr_bin, fraddr_str);
			strcpy(friendPubKey_C,fraddr_str);
			friendPubKey_C[TOX_PUBLIC_KEY_SIZE*2] = '\0';
			printf("friend public key is %s\n", fraddr_str);
			memcpy(friendPubKey,friendPubKey_C,strlen(friendPubKey_C));
			return 0;
		 }
	}
	return -1;
}

/* GetFriendNumInFriendlist
** Input the friend ID and get the friend num back
** After the app get the friend p2p ID from the block chain, app may call this function the get the friendnum
** The friend num may be quite useful in the other function
** -1 qlinkNode is not valid
** -2 invalid input friendId
** -3 friend not in list
** >=0 the friend num
*/
int GetFriendNumInFriendlist(char * friendId_P)
{
	
	if(qlinkNode != NULL)
	{

		if(friendId_P == NULL)
		{
			return -2;
		}
//		printf("GetFriendNumInFriendlist Frined ID is %s, %d", friendId_P, strlen(friendId_P));
		uint8_t *friendId_bin = hex_string_to_bin(friendId_P);
//		printf("GetFriendNumInFriendlist friendId_bin is %s, %d", friendId_bin, strlen(friendId_bin));
		
		int friendLoc = tox_friend_get_Num_in_friendlist(qlinkNode, friendId_bin, NULL);
		printf("This friend loc is %d\n", friendLoc);

		free(friendId_bin);
		if (friendLoc == -1) 
		 { 
			return -3;
		 }
		else
			return friendLoc;
	}
	return -1;
	
}


/* Get friend connection status
** input the friendnum to get the status of the connection between app itself and the friend
** 0 not connected
** 1 tcp connected
** 2 udp connected
** android app must check this first before request the wifi password of the friend
** -1 qlinkNode not valid
** -3 invalid friendNum
**-4  invalid p2pid
*/
int GetFriendConnectionStatus(char *p2pid)
{
	if(qlinkNode != NULL)
	{
		if(p2pid==NULL)
			return -4;
		int friendNum=GetFriendNumInFriendlist(p2pid);
		if(friendNum<0)
		{
			return -3;
		}
		switch(tox_friend_get_connection_status(qlinkNode,friendNum,NULL))
		{
			case TOX_CONNECTION_NONE:
				return 0;
				break;
			case TOX_CONNECTION_TCP:
				return 1;
				break;
			case TOX_CONNECTION_UDP:
				return 2;
				break;
			default:
				return -2;
				break;
			
		}
	}
	return -1;
}

/* SaveWifiPassword
** save the wifi password, ssid, mac of the wifi owner
** android app shall call this function for wifi owner
** ssid and mac is not check right now, will add later
** 0 saved ok
** -1 qlinkNode not valid
** -2 password invalid
** -3/-4/-5 password file error
*/

/*
{
	"WIFIINFO":	[{
			"WIFINUM":	1,
			"SSID":	"zhijiehome",
			"MAC":	"00:0c:29:86:d9:94",
			"PASSWORD":	"m8987",
			"SAVETIME":	"2017-12-12 17:19:14"
		}]
}
*/

int SaveWifiPassword(char* password,char * ssid_name,char * mac_addr)
{
	if(qlinkNode != NULL)
	{
		if(password==NULL) {
			return -9;
        }
		
		if(ssid_name==NULL) {
			return -10;
        }
		
		if(mac_addr==NULL) {
			return -11;
        }						

		if(pass_data_file == NULL) {
			return -8;
        }
		printf("\npassword file is %s\n",pass_data_file);

		int wifiLoc = 0;
		int allSavedNum = 0;
		wifiNodeInfo *wifiNodeInfo_tmp = NULL;
		printf("search SSID %s, mac addr %s\n",ssid_name,mac_addr);
		if(wifiNodeInfo_H == NULL)
		{
			/*No init or no data save before, need to check the password file first*/
			
			allSavedNum = cJSON_WIFIINFO_to_struct_array(ssid_name,mac_addr,&wifiLoc,&wifiNodeInfo_tmp);
			printf("All saved wifi is %d , find the wifi in saved num is %d\n", allSavedNum,wifiLoc);
			
			//savedWifiNum = allSavedNum;
		}
		else
		{
			//
			find_wifi_in_wifiList(ssid_name,mac_addr,&wifiLoc,&wifiNodeInfo_tmp);
			printf("All saved wifi is mem %d , find the wifi in saved num is %d", savedWifiNum,wifiLoc);
		}
		 char timemsg[100];
		time_t rawtime;
		struct tm *timeinfo;
		time(&rawtime);
		timeinfo = localtime(&rawtime);
	    strftime(timemsg,100,"%Y-%m-%d %H:%M:%S",timeinfo);
		printf("%s\n",timemsg);
		
		if(wifiNodeInfo_tmp != NULL)
		{
			printf("There is same wifi saved");
			strcpy(wifiNodeInfo_tmp->password,password);
			strcpy(wifiNodeInfo_tmp->saveTime,timemsg);
		}
		else
		{
			wifiNodeInfo_tmp = (wifiNodeInfo *)malloc(sizeof(wifiNodeInfo));
			if(wifiNodeInfo_tmp == NULL)
			{
				printf("wifiNodeInfo_tmp malloc fail\n");
				return -8;
			}
			if(wifiNodeInfo_H == NULL)
			{
				wifiNodeInfo_H = wifiNodeInfo_tmp;
				wifiNodeInfo_C = wifiNodeInfo_tmp;
			}
			else
			{
				wifiNodeInfo_C->Nextwifinfo_p = wifiNodeInfo_tmp;
				wifiNodeInfo_C = wifiNodeInfo_tmp;
			}
			savedWifiNum ++;
			wifiNodeInfo_tmp->wifinum = savedWifiNum;
			strcpy(wifiNodeInfo_tmp->ssid,ssid_name);
			strcpy(wifiNodeInfo_tmp->macadd,mac_addr);
			strcpy(wifiNodeInfo_tmp->password,password);
			strcpy(wifiNodeInfo_tmp->saveTime,timemsg);
			wifiNodeInfo_tmp->Nextwifinfo_p = NULL;

			
		}

		/*Mem to Json*/
		char *passWord_save = Create_JSON_From_WifiNode();
		FILE *data_file = fopen(pass_data_file, "w");
	    if (!data_file) {
	        perror("[!] load_key");
			return -3;
	    }
        
	    if (fwrite(passWord_save, sizeof(uint8_t), strlen(passWord_save), data_file) != strlen(passWord_save)) {
	        fputs("[!] could not write data file (1)!", stderr);
			free(passWord_save);
	        return -4;
	    }

	    if (fclose(data_file) < 0) {
	        perror("[!] could not write data file (2)");
			free(passWord_save);
			return -5;
	        
	    }
		
        free(passWord_save);	
	}
	else
    {   
		return -1;
    }
    
	return 0;
}

/* SendWifiPasswordRequest
** Send request to get the wifi password of the friend
** the owner may have several wifi asset, so specific the ssid and mac
** ssid and mac is not check right now, will add later
** 0 saved ok
** -1 qlinkNode not valid
*/


/*
	share pass word Json
	{
		type: "password",
		ssid:"zhijie"
		mac:"ui32"
	}
*/
int SendWifiPasswordRequest(int friendNum, char* ssid_name, char* mac_addr)
{
	if(qlinkNode != NULL)
	{ 	
		if(ssid_name==NULL)
			return -4;
		if(mac_addr==NULL)
			return -5;		

		char *wifipasswordRequest = Create_JSON_Request_Wifi_Pass(ssid_name,mac_addr);
		//tox_friend_send_message(qlinkNode, friendNum, TOX_MESSAGE_TYPE_NORMAL, requstWifi, strlen(requstWifi), NULL);
		tox_friend_send_message(qlinkNode, friendNum, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *)wifipasswordRequest, strlen(wifipasswordRequest), NULL);
		free(wifipasswordRequest);
#if 0
		/*Just for test*/
		//receive request
		friend_Message_process(qlinkNode,friendNum,wifipasswordRequest);
		free(wifipasswordRequest);
		//receive response
		char *wifipasswordResponse = Create_JSON_Response_Wifi_Pass(ssid_c_p,mac_c_p,"testPwd");
		friend_Message_process(qlinkNode,friendNum,wifipasswordResponse);
		free(wifipasswordResponse);
		//receive no saved
		//char *wifinopasswordResponse = Create_JSON_Response_no_Wifi_Pass(ssid_c_p,mac_c_p);
		//friend_Message_process(qlinkNode,friendNum,wifinopasswordResponse);
		//free(wifinopasswordResponse);
		
#endif		
		return 0;        
    }
		
	else
			return -1;
}


/* GetWifiPassword
** after GetWifiPassword, app could can this fucntion to get the wifi password
** the owner may have several wifi asset, so specific the ssid and mac
** ssid and mac is not check right now, will add later
** 0 Got the Password
** -1 qlinkNode not valid
** -1 qlinkNode not valid
** -2 Friend has no save Pass, don't need to wait
** -3 Friend still not response, can keep wait
*/

int GetWifiPassword(int friendNum, char * ssid_name_p, char *  mac_addr_p,char *  password)
{
	if(qlinkNode != NULL)
	{ 	
		if(ssid_name_p==NULL)
			return -4;
		if(mac_addr_p==NULL)
			return -5;

		int result = tox_friend_Get_wifiPassWord(qlinkNode, friendNum, ssid_name_p, mac_addr_p, password, NULL);
		if(result == 0)
		{
			printf("Got the Password \n");
			return 0;  
		}
			 
		else if(result == -2)
		{
			printf("Friend has no save Pass, don't need to wait\n");
			return -2;  
		}
		else
		{
			printf("Friend still not response, can keep wait\n");
			return -3; 
		}
			
		     
    }
		
	else
		return -1;
}

//parse a struct array  
int cJSON_WIFIINFO_to_struct_array(char *ssid,char *macaddr,int *wifiNum,wifiNodeInfo **wifiNodeInfo_p)  
{  
    cJSON *json,*arrayItem,*item,*object;  
    int i;  

  	

	printf("password file is %s\n",pass_data_file);
	FILE *data_file = fopen(pass_data_file, "r");

    if (data_file) 
	{
        fseek(data_file, 0, SEEK_END);
        size_t size = ftell(data_file);
        rewind(data_file);

        
		VLA(uint8_t, data, (size+1));
		
		memset(data,0,(size+1));
		

        if (fread(&data[0], sizeof(uint8_t), size, data_file) != size) {
            fputs("[!] could not read data file!\n", stderr);
            fclose(data_file);
            
        }
		else
		{
			data[(size)] = '\0';
			printf("Saved data file content is %s", data);
			fclose(data_file);
			 
    	}

		json=cJSON_Parse((char *)data);  
    	if (!json)  
	    {  
	        printf("Error before: [%s]\n",cJSON_GetErrorPtr());  
			return -3;
	    }  
   	 	else  
	    {  
	    /*
	    	{
		"WIFIINFO":	
		[{
			"WIFINUM":	1,
			"SSID":	"zhijiehome",
			"MAC":	"00:0c:29:86:d9:94",
			"PASSWORD":	"m8987",
			"SAVETIME":	"2017-12-12 17:19:14"
		}]
		}
	    */
	    	int wifisize = 0;
	        arrayItem=cJSON_GetObjectItem(json,"WIFIINFO");  
	        if(arrayItem!=NULL)  
	        {  
	            wifisize=cJSON_GetArraySize(arrayItem);  
	            printf("cJSON_GetArraySize: size=%d\n",wifisize); 

				wifiNodeInfo *wifiNodeInfo_tmp = NULL;
				bool ssidfound = false;
	  
	            for(i=0;i<wifisize;i++)  
	            {  
	                printf("i=%d\n",i);  
					ssidfound = false;
					/*Init local memory info for wifiinfo*/

					wifiNodeInfo_tmp = (wifiNodeInfo *)malloc(sizeof(wifiNodeInfo));
					
					if(wifiNodeInfo_tmp == NULL)
					{
						printf("wifiNodeInfo_tmp malloc fail\n");
						return -2;
					}
					wifiNodeInfo_tmp->Nextwifinfo_p = NULL;
					if(wifiNodeInfo_H == NULL)
					{
						wifiNodeInfo_H = wifiNodeInfo_tmp;
						wifiNodeInfo_C = wifiNodeInfo_tmp;
					}
					else
					{
						wifiNodeInfo_C->Nextwifinfo_p = wifiNodeInfo_tmp;
						wifiNodeInfo_C = wifiNodeInfo_tmp;
					}
					savedWifiNum ++;
					
	                object=cJSON_GetArrayItem(arrayItem,i);  
	  
	                item=cJSON_GetObjectItem(object,"WIFINUM");  
	                if(item!=NULL)  
	                {  
	                    printf("cJSON_GetObjectItem: type=%d, string is %s, value is %d\n",item->type,item->string,item->valueint);  
	                    //memcpy(worker[i].firstName,item->valuestring,strlen(item->valuestring));  
	                    wifiNodeInfo_tmp->wifinum =  item->valueint;
	                }  
	  
	                item=cJSON_GetObjectItem(object,"SSID");  
	                if(item!=NULL)  
	                {  
	                    printf("cJSON_GetObjectItem: type=%d, string is %s, valuestring=%s\n",item->type,item->string,item->valuestring);  
						//printf("\nsearch ssid %s, saved ssid %s\n",ssid,wifiNodeInfo_tmp->ssid);
						strcpy(wifiNodeInfo_tmp->ssid,item->valuestring);
						printf("\n search ssid %s, saved ssid %s\n",ssid,wifiNodeInfo_tmp->ssid);
						if(strcmp(ssid,wifiNodeInfo_tmp->ssid)==0)
						{
							ssidfound = true;
							printf("Found ssid\n");
						}
							
	                }  
	  
	                item=cJSON_GetObjectItem(object,"MAC");  
	                if(item!=NULL)  
	                {  
	                    printf("cJSON_GetObjectItem: type=%d, string is %s, valuestring=%s\n",item->type,item->string,item->valuestring);  
	                    //memcpy(wifiNodeInfo_tmp->macadd,item->valuestring,strlen(item->valuestring));
						strcpy(wifiNodeInfo_tmp->macadd,item->valuestring);
						printf("\nsearch mac %s, saved mac %s\n",macaddr,wifiNodeInfo_tmp->macadd);
						if((ssidfound == true)&&(strcmp(macaddr,wifiNodeInfo_tmp->macadd)==0))
						{
							printf("Found the wifi in password list, wifinum is %d\n", wifiNodeInfo_tmp->wifinum);
							*wifiNum = wifiNodeInfo_tmp->wifinum;
							*wifiNodeInfo_p = wifiNodeInfo_tmp;
						}
	                }  
	  
	                item=cJSON_GetObjectItem(object,"PASSWORD");  
	                if(item!=NULL)  
	                {  
	                    printf("cJSON_GetObjectItem: type=%d, string is %s, valuestring=%s\n",item->type,item->string,item->valuestring);  
	                    strcpy(wifiNodeInfo_tmp->password,item->valuestring); 
	                }  
	                else  
	                {  
	                    printf("cJSON_GetObjectItem: get password failed\n");  
	                }  
	  
	                item=cJSON_GetObjectItem(object,"SAVETIME");  
	                if(item!=NULL)  
	                {  
	                    printf("cJSON_GetObjectItem: type=%d, string is %s, valuestring=%s\n",item->type,item->string,item->valuestring);  
	                    strcpy(wifiNodeInfo_tmp->saveTime,item->valuestring); 
	                }  
	            }  
	        }  
	  
	       
	  
	        cJSON_Delete(json);  
			return wifisize;
	    }  
    
	}
	else
	{
		//no wifi pass word data saved ,return
		*wifiNum = 0;
		wifiNodeInfo_p = NULL;
			
		return -1;
		
	}

    return 0;  
}  

int find_wifi_in_wifiList(char *ssid,char *macaddr,int *wifiNum,wifiNodeInfo **wifiNodeInfo_p)
{
	wifiNodeInfo *wifiNodeInfo_tmp = NULL;
	wifiNodeInfo_tmp = wifiNodeInfo_H;

	while(wifiNodeInfo_tmp != NULL)
	{
		if((strcmp(ssid,wifiNodeInfo_tmp->ssid)==0)
			&&(strcmp(macaddr,wifiNodeInfo_tmp->macadd)==0))
		{
			printf("Found the wifi in password list, wifinum is %d\n", wifiNodeInfo_tmp->wifinum);
			*wifiNum = wifiNodeInfo_tmp->wifinum;
			*wifiNodeInfo_p = wifiNodeInfo_tmp;
			return 0;
		}
		wifiNodeInfo_tmp = wifiNodeInfo_tmp->Nextwifinfo_p;
	}
	return -1;
}

char*  Create_JSON_From_WifiNode()
{
   cJSON  *wifiJson,*pJsonArry,*pJsonsub;
   wifiNodeInfo *wifiNodeInfo_tmp = wifiNodeInfo_H;

    wifiJson = cJSON_CreateObject();
  	if(NULL == wifiJson)
  	{
          //error happend here
          return NULL;
    }
   pJsonArry=cJSON_CreateArray();   /*\u521b\u5efa\u6570\u7ec4*/
   cJSON_AddItemToObject(wifiJson,"WIFIINFO", pJsonArry);
   while(wifiNodeInfo_tmp != NULL)
   {
   		cJSON_AddItemToArray(pJsonArry,pJsonsub=cJSON_CreateObject()); 

		cJSON_AddNumberToObject(pJsonsub,"WIFINUM", wifiNodeInfo_tmp->wifinum);
   		cJSON_AddStringToObject(pJsonsub, "SSID",wifiNodeInfo_tmp->ssid);                     
   		cJSON_AddStringToObject(pJsonsub, "MAC",wifiNodeInfo_tmp->macadd);                                        
   		cJSON_AddStringToObject(pJsonsub, "PASSWORD",wifiNodeInfo_tmp->password);                                                         
   		cJSON_AddStringToObject(pJsonsub, "SAVETIME",wifiNodeInfo_tmp->saveTime);  
		wifiNodeInfo_tmp = wifiNodeInfo_tmp->Nextwifinfo_p;
   	                                    
   
   }
   printf("Create Jason\n");
   char * pp = cJSON_Print(wifiJson);
   
   if(NULL == pp)
   {
      cJSON_Delete(wifiJson);
      return NULL;
   }
   printf("Create_JSON_From_WifiNode end %s\n", pp);
   free(pp);
   cJSON_Delete(wifiJson);
   return pp;
}


/*
	share pass word Json
	{
		type: "Getpassword",
		ssid:"zhijie"
		mac:"ui32"
	}
*/

char*  Create_JSON_Request_Wifi_Pass(char *ssid,char *macaddr)
{
   cJSON  *requestWifiPassJson;
   requestWifiPassJson = cJSON_CreateObject();
	if(NULL == requestWifiPassJson)
	{
		  //error happend here
		  return NULL;
	}
   
	cJSON_AddStringToObject(requestWifiPassJson,"type", requstWifiJSON);
	cJSON_AddStringToObject(requestWifiPassJson, "ssid",ssid);					  
	cJSON_AddStringToObject(requestWifiPassJson, "mac",macaddr);										  
									
   
   
   printf("Create_JSON_Request_Wifi_Pass\n");
   char * pp = cJSON_Print(requestWifiPassJson);
   
   if(NULL == pp)
   {
	  cJSON_Delete(requestWifiPassJson);
	  return NULL;
   }
   printf("Create_JSON_Request_Wifi_Pass %s\n", pp);
   free(pp);
   cJSON_Delete(requestWifiPassJson);
   return pp;
}

char*  Create_JSON_Response_Wifi_Pass(char *ssid,char *macaddr,char *password)
{
   cJSON  *requestWifiPassJson;
   requestWifiPassJson = cJSON_CreateObject();
	if(NULL == requestWifiPassJson)
	{
		  //error happend here
		  return NULL;
	}
   
	cJSON_AddStringToObject(requestWifiPassJson,"type", AnswerWifiJSON);
	cJSON_AddStringToObject(requestWifiPassJson, "ssid",ssid);					  
	cJSON_AddStringToObject(requestWifiPassJson, "mac",macaddr);
	cJSON_AddStringToObject(requestWifiPassJson, "password",password);
	
   
   printf("Create_JSON_Response_Wifi_Pass\n");
   char * pp = cJSON_Print(requestWifiPassJson);
   
   if(NULL == pp)
   {
	  cJSON_Delete(requestWifiPassJson);
	  return NULL;
   }
   printf("Create_JSON_Response_Wifi_Pass %s\n", pp);
   free(pp);
   cJSON_Delete(requestWifiPassJson);
   return pp;
}

char*  Create_JSON_Response_no_Wifi_Pass(char *ssid,char *macaddr)
{
   cJSON  *requestWifiPassJson;
   requestWifiPassJson = cJSON_CreateObject();
	if(NULL == requestWifiPassJson)
	{
		  //error happend here
		  return NULL;
	}
   
	cJSON_AddStringToObject(requestWifiPassJson,"type", AnswerNoSavePassJSON);
	cJSON_AddStringToObject(requestWifiPassJson, "ssid",ssid);					  
	cJSON_AddStringToObject(requestWifiPassJson, "mac",macaddr);
	//cJSON_AddStringToObject(requestWifiPassJson, "password",password);
	
   
   printf("Create_JSON_Response_no_Wifi_Pass\n");
   char * pp = cJSON_Print(requestWifiPassJson);
   
   if(NULL == pp)
   {
	  cJSON_Delete(requestWifiPassJson);
	  return NULL;
   }
   printf("Create_JSON_Response_no_Wifi_Pass %s\n", pp);
   free(pp);
   cJSON_Delete(requestWifiPassJson);
   return pp;
}


/* SendRequest
** 0 SendRequest ok
** -1 qlinkNode not valid
** -2 message or p2pid not valid
** -3 friend_not_valid
*/

int SendRequest(char * p2pid,char * message_c)
{
	if(qlinkNode != NULL)
	{ 	
		if(message_c == NULL||p2pid==NULL)
			return -2;
		int friendNum=GetFriendNumInFriendlist(p2pid);
		if (friend_not_valid_Qlink(qlinkNode, friendNum))
		{
        	return -3;
    	}
		tox_friend_send_message(qlinkNode, friendNum, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *)message_c, strlen(message_c), NULL);
		//free(message_c);
		return 0;        
    }
		
	else
		return -1;
}

/* Addfilesender
** >0 file Send ok
** -1 qlinkNode not valid
** -2 filename or p2pid not valid
** -3 friendnum not valid
** -4 file open fail
** -5 file send fail
*/


int Addfilesender ( int friendnum, char* filename )
{
	if ( qlinkNode != NULL )
	{
		DEBUG_PRINT(DEBUG_LEVEL_INFO,"filename:%s",filename );
		if ( filename == NULL )
		{
			return -2;
		}
		if ( friend_not_valid_Qlink ( qlinkNode, friendnum ) )
		{
			return -3;
		}

		FILE* tempfile = fopen ( filename, "rb" );

		if ( tempfile == 0 )
		{
			return -4;
		}

		fseek ( tempfile, 0, SEEK_END );
		uint64_t filesize = ftell ( tempfile );
		fseek ( tempfile, 0, SEEK_SET );
		uint32_t filenum = tox_file_send ( qlinkNode, friendnum, TOX_FILE_KIND_DATA, filesize, 0, ( uint8_t* ) filename,
		                                   strlen ( filename ), 0 );

		if ( filenum == -1 )
		{
			return -5;
		}

		file_senders[numfilesenders].file = tempfile;
		file_senders[numfilesenders].friendnum = friendnum;
		file_senders[numfilesenders].filenumber = filenum;
		++numfilesenders;
		return filenum;
	}
	else
	{
		return -1;
	}

}

/*20180306,wenchao,add Created new group chat interface,begin*/
  
/* CreatedNewGroupChat
** groupnum: Created success
** -1: qlinkNode not valid
** -2: Created fail
*/
  
int CreatedNewGroupChat()
{
	if(qlinkNode != NULL)
	{
		int groupnum=tox_conference_new(qlinkNode, NULL);
		if(groupnum==-1)
		{
			printf("Created new group chat fail\n");
			return -2;
		}
		return groupnum;
	}
	else
	{
		return -1;
	}
}

/*20180306,wenchao,add Created new group chat interface,end*/
int CreatedNewGroupChatForAsset()
{
	if ( ( strlen ( assetInfo ) !=0 ) && ( assetInfo!=NULL ) )
	{
		cJSON* curAsset = cJSON_Parse ( assetInfo );
		cJSON* pJsonArry = cJSON_GetObjectItem ( curAsset,"VPNINFO" );
		int vpnAssetSize =0,i=0;
		if ( pJsonArry!=NULL )
		{
			vpnAssetSize=cJSON_GetArraySize ( pJsonArry );
			for ( i=0; i<vpnAssetSize; i++ )
			{
				CreatedNewGroupChat();
			}
		}
	}
	else
	{
		//printf ( "No asset info\n" );
	}
	return 0;
}
	
/*20180306,wenchao,add Invite friend to group chat interface,begin*/

  
/* InviteFriendToGroupChat
** 0: Invite success
** -1: qlinkNode not valid
** -2: Invite fail
** -3 friendnum not valid
*/

int InviteFriendToGroupChat(char * p2pid,int groupnumber)
{
	if(qlinkNode != NULL)
	{
		if(p2pid==NULL)
			return -4;
		int friendnumber=GetFriendNumInFriendlist(p2pid);
		if (friend_not_valid_Qlink(qlinkNode, friendnumber))
		{
        	return -3;
    	}
		bool IsInviteOK=tox_conference_invite(qlinkNode, friendnumber, groupnumber, NULL);
		if(IsInviteOK==false)
		{
			printf("Invite friend to group chat fail\n");
			return -2;
		}
		else
		{
			printf("Invite friend to group chat success\n");
		}
		return 0;
	}
	else
		return -1;	
}

/*20180306,wenchao,add Invite friend to group chat interface,end*/


/*20180306,wenchao,add send message to group chat interface,begin*/


/* SendMessageToGroupChat
** 0: send message success
** -1: qlinkNode not valid
** -2: message is  null
** -3 send message fail
*/

int SendMessageToGroupChat(int groupnumber, char* message)
{
	if(qlinkNode != NULL)
	{
		if(message==NULL)
			return -4;
		bool res = tox_conference_send_message(qlinkNode, groupnumber, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *)message, strlen(message),NULL);
        if (res == true) {
			//printf("send message to group chat success\n");
			 printf("send message to group chat success, group no. %u: %i\n", groupnumber, res);
        } else {
            printf("could not send message to group no. %u: %i\n", groupnumber, res);
			return -3;
        }
    	return 0;
	}
	else
		return -1;
	
}

/*20180306,wenchao,add send message to group chat interface,end*/


int setcallback(FriendStatusChange fsc,SelfStatusChange ssc,MessageProcess mp,FileProcess fp,GroupChatMessageProcess gcmp,SendGroupNum sgn,GetJson gj,GetPath gp)
{
	if(fsc!=NULL&&ssc!=NULL&&mp!=NULL&&fp!=NULL&&gcmp!=NULL&&sgn!=NULL&&gj!=NULL&&gp!=NULL)
	{
		friendstatuschage=fsc;
		selfstatuschange=ssc;
		messageprocess=mp;
		fileprocess=fp;
		groupchatmessageprocess=gcmp;
		sendgroupnum=sgn;
		getjson=gj;
		getpath=gp;
	}
	else
		return -1;
	return 0;
}

/* DeleteFriendAll
** Delete All friend
** 0 success
** -1 qlinkNode not valid
** -2 delete fail
*/
int DeleteFriendAll()
{
	if(qlinkNode != NULL)
	{
		int friendcounts=tox_self_get_friend_list_size(qlinkNode);
		int i;
		for(i=0;i<friendcounts;i++)
		{
			int res = tox_friend_delete(qlinkNode, friendcounts-1-i, NULL);
       		 if (res) {
            	printf("remove a friend success\n");
				//save_data(qlinkNode);
        	 } else {
            	printf("remove a friend fail\n");
				return -2;
        	}
		}
		return 0;
			
	}
	return -1;
}

int gethomedir(void)
{
	char* home;
	home = getenv ( "HOME" );
	char* filepath=strcat ( home,"/QLCChain/" );
	if ( filepath!=NULL )
	{
		if ( access ( filepath,0 ) ==-1 )
		{
			if ( mkdir ( filepath,0777 ) )
			{
				DEBUG_PRINT(DEBUG_LEVEL_INFO, "creat file bag failed!!!" );
				strcpy ( homeDirPath,"/home/" );
				return 1;
			}
		}
	}
	else
	{
		strcpy ( homeDirPath,"/home/" );
		return 2;
	}
	strcpy (homeDirPath,filepath);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "gethomedir:homeDirPath(%s)",homeDirPath);
	return 0;
}

int readvpnAssetfile()
{
	char filepath_name[200] = {0};

    strcpy(filepath_name, QLV_TOPDIR);
	strcat(filepath_name, DEFAULT_VPNASSET_FILENAME);

    FILE *data_file = fopen(filepath_name, "r");
	if (data_file) {
		fseek(data_file, 0, SEEK_END);
		size_t size = ftell(data_file);
		rewind(data_file);

		VLA(uint8_t, data, size);

		if (fread(data, sizeof(uint8_t), size, data_file) != size) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "asset file read error");
			fclose(data_file);
			return -1;
		}

		fclose(data_file);
		strncpy(assetInfo, (char *)data, size);
	}
    
	return 0;
}

int writep2pidtofile ( char* id )
{
	if ( id==NULL )
	{
		return -1;
	}
	char filepath_name[200]= {0};
    strcpy(filepath_name,QLV_P2PID_FILE);
	FILE* data_file = fopen ( filepath_name, "w" );

	if ( !data_file )
	{
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "open file error in writep2pidtofile func" );
		return -2;
	}
	if ( fwrite ( id, sizeof ( uint8_t ), strlen ( id ), data_file ) != strlen ( id ) )
	{
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "write file error in writep2pidtofile func" );
		fclose ( data_file );
		return -3;
	}

	if ( fclose ( data_file ) < 0 )
	{
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "close file error in writep2pidtofile func" );
		return -4;
	}
	return 0;
}

int addvpnAsset(char* vpnName,char* username,char* password,char* privatekey,char* vpnfileName)
{
	char filepath_name[200] = {0};
    
	strcpy(filepath_name, QLV_TOPDIR);
	strcat(filepath_name, DEFAULT_VPNASSET_FILENAME);

    if (!strlen(vpnName) || !strlen(vpnfileName)) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "vpnname or filename null");
        return -1;
    }

	if (strlen(assetInfo)) {
		cJSON *curAsset = cJSON_Parse(assetInfo);
		cJSON *pJsonArry = cJSON_GetObjectItem(curAsset, "VPNINFO");
		int vpnAssetSize = 0, i = 0;
        
		if (!curAsset) {
			return -1;
		}
        
		if (!pJsonArry) {
			cJSON_Delete(curAsset);
			return -2;
		}
        
		vpnAssetSize = cJSON_GetArraySize(pJsonArry);
		for (i = 0; i < vpnAssetSize; i++) {
			cJSON *object = cJSON_GetArrayItem(pJsonArry, i);

            if (object) {
				cJSON *item = cJSON_GetObjectItem(object, "vpnName");

                if (item) {
					if (!strcmp(vpnName, item->valuestring)) {
						cJSON *vpnAssetreplace = cJSON_CreateObject();
						cJSON *Groupnum = cJSON_GetObjectItem(object, "Groupnum");
						cJSON_AddStringToObject(vpnAssetreplace, "vpnName", vpnName);
						cJSON_AddStringToObject(vpnAssetreplace, "userName", username);
						cJSON_AddStringToObject(vpnAssetreplace, "password", password);
						cJSON_AddStringToObject(vpnAssetreplace, "privateKey", privatekey);
						cJSON_AddNumberToObject(vpnAssetreplace, "Groupnum", Groupnum->valueint);
						cJSON_AddStringToObject(vpnAssetreplace, "vpnfileName", vpnfileName);
						cJSON_ReplaceItemInArray(pJsonArry, i, vpnAssetreplace);
						break;
					}
				}
			}
		}
        
		if (i == vpnAssetSize) {
			int groupnum = CreatedNewGroupChat();
			cJSON *vpnAssetsub = cJSON_CreateObject();
			cJSON_AddStringToObject(vpnAssetsub, "vpnName", vpnName);
			cJSON_AddStringToObject(vpnAssetsub, "userName", username);
			cJSON_AddStringToObject(vpnAssetsub, "password", password);
			cJSON_AddStringToObject(vpnAssetsub, "privateKey", privatekey);
			cJSON_AddNumberToObject(vpnAssetsub, "Groupnum", groupnum);
			cJSON_AddStringToObject(vpnAssetsub, "vpnfileName", vpnfileName);
			cJSON_AddItemToArray(pJsonArry, vpnAssetsub);
		}

		char *asset = cJSON_Print(curAsset);
		if (!asset) {
			cJSON_Delete(curAsset);
			return -3;
		}
        
		memset(assetInfo, 0x00, sizeof(assetInfo));
		strcpy(assetInfo, asset);
        free(asset);
		cJSON_Delete(curAsset);
        
		FILE *data_file = fopen(filepath_name, "w");
		if (!data_file) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "open file error in addvpnAsset func");
			return -4;
		}
        
		if (fwrite(assetInfo, sizeof(uint8_t), strlen(assetInfo), data_file) != strlen(assetInfo)) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "write file error in addvpnAsset func");
			fclose(data_file);
			return -5;
		}

		fclose(data_file);
	} else {
		int groupnum = CreatedNewGroupChat();
		cJSON *vpnAsset = cJSON_CreateObject();
		if (!vpnAsset) {
			return -7;
		}
        
		cJSON *pJsonArry = cJSON_CreateArray();
		if (!pJsonArry) {
			cJSON_Delete(vpnAsset);
			return -7;
		}
        
		cJSON *vpnAssetsub = cJSON_CreateObject();
		if (!vpnAssetsub) {
			cJSON_Delete(vpnAsset);
			cJSON_Delete(pJsonArry);
			return -7;
		}
		cJSON_AddItemToObject(vpnAsset, "VPNINFO", pJsonArry);

		cJSON_AddStringToObject(vpnAssetsub, "vpnName", vpnName);
		cJSON_AddStringToObject(vpnAssetsub, "userName", username);
		cJSON_AddStringToObject(vpnAssetsub, "password", password);
		cJSON_AddStringToObject(vpnAssetsub, "privateKey", privatekey);
		cJSON_AddNumberToObject(vpnAssetsub, "Groupnum", groupnum);
		cJSON_AddStringToObject(vpnAssetsub, "vpnfileName", vpnfileName);

		cJSON_AddItemToArray(pJsonArry, vpnAssetsub);

        char *asset = cJSON_Print(vpnAsset);
		if (!asset) {
			cJSON_Delete(vpnAsset);
			return -8;
		}
        
		DEBUG_PRINT(DEBUG_LEVEL_INFO, "asset: %s", asset);

        memset(assetInfo, 0x00, sizeof(assetInfo));
		strncpy(assetInfo, asset, sizeof(assetInfo) - 1);
        free(asset);
		cJSON_Delete(vpnAsset);

		FILE *data_file = fopen(filepath_name, "w");
		if (!data_file) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "open error in addvpnAsset func");
			return -9;
		}
        
		if (fwrite(assetInfo, sizeof(uint8_t), strlen(assetInfo), data_file) != strlen(assetInfo)) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "write error in addvpnAsset func");
			fclose(data_file);
			return -10;
		}

		fclose(data_file);
	}
    
	return 0;
}

int trave_dir ( char filename[256][256],int depth )
{
	DIR *d;
	int len = 0;
	struct dirent *file;

	if (!(d = opendir(g_vpn_file_dir))) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "trave_dir open path(%s) error", g_vpn_file_dir);
		return -1;
	}
    
	while ((file = readdir(d))) {
		if (strncmp(file->d_name, ".", 1) == 0) {
			continue;
		}
        
		strcpy(filename[len++], file->d_name);
	}
    
	closedir(d);
	return len;
}

/*20180306,wenchao,add Invite friend to group chat interface,begin*/
int processCheckConnectReq ( cJSON* pJson,int friendnum )
{
	cJSON *CheckConnectRspJson = NULL;
    cJSON *data = NULL;

	if (!pJson) {
	    DEBUG_PRINT(DEBUG_LEVEL_ERROR, "CheckConnectRspJson NULL");
		return -1;
	}

    CheckConnectRspJson = pJson;
    
	cJSON_DeleteItemFromObject(CheckConnectRspJson, "type");
	cJSON_AddStringToObject(CheckConnectRspJson, "type", checkConnectRsp);

    data = cJSON_GetObjectItem(pJson, "data");
    cJSON *dataJson = cJSON_Parse(data->valuestring);
    if (!dataJson) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "parse data json fail");
        return -1;
    }
    
    cJSON_AddNumberToObject(dataJson, "version", SERVER_VERSION);
    char *datastr = cJSON_PrintUnformatted(dataJson);
    cJSON_ReplaceItemInObject(CheckConnectRspJson, "data", cJSON_CreateString(datastr));
    free(datastr);
    cJSON_Delete(dataJson);
    
	char *CheckConnectRsp = cJSON_PrintUnformatted(CheckConnectRspJson);
	if (!CheckConnectRsp) {
	    DEBUG_PRINT(DEBUG_LEVEL_ERROR, "cprocessCheckConnectReq NULL");
		return -2;
	}
    
	if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
        (uint8_t *)CheckConnectRsp, strlen(CheckConnectRsp), NULL) < 1) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "could not send CheckConnectRsp to friend num %u", friendnum);
	} else {
		DEBUG_PRINT(DEBUG_LEVEL_INFO, "send(%s) OK", CheckConnectRsp);
	}

    free(CheckConnectRsp);
	return 0;
}

/*****************************************************************************
 函 数 名  : tox_send_msg_thread
 功能描述  : 消息发送线程
 输入参数  : void *args  
 输出参数  : 无
 返 回 值  : void
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月19日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
void *tox_send_msg_thread(void *args)
{
    struct tox_msg_send *pos = NULL;
    struct tox_msg_send *n = NULL;
    int nowtime = time(NULL);
    
    while (1) {
        if (list_empty(&g_tox_msg_send_list)) {
            usleep(50000);
            continue;
        }

        nowtime = time(NULL);

        pthread_rwlock_wrlock(&g_tox_msg_send_lock);
        list_for_each_entry_safe(pos, n, &g_tox_msg_send_list, list) {
            if (pos->sendtimes >= 3) {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "send msg(%d) failed", pos->msgid);
                list_del(&pos->list);

                if (pos->msg) {
                    free(pos->msg);
                }
                
                free(pos);
                continue;
            }

            if (nowtime - pos->lastsendtime >= 3) {
                tox_friend_send_message(qlinkNode, pos->friendnum, 
                    TOX_MESSAGE_TYPE_NORMAL, (uint8_t *)pos->bufmsg, strlen(pos->bufmsg), NULL);
				//DEBUG_PRINT(DEBUG_LEVEL_INFO, "send msg(%s)", pos->bufmsg);
				pos->sendtimes++;
                pos->lastsendtime = time(NULL);
            }
        }
        pthread_rwlock_unlock(&g_tox_msg_send_lock);
    }
}

char filename[256][256] = {0};

int processSendVpnFileRequest(cJSON *pJson, int friendnum)
{    
    if (!pJson) {
		return -1;
	}
    
	cJSON *data_info = cJSON_GetObjectItem(pJson, "data");
	if (!data_info) {
		return -2;
	}
    
	data_info = cJSON_Parse(data_info->valuestring);
	if (!data_info) {
		return -2;
	}
    
	cJSON *vpnNameJson = cJSON_GetObjectItem(data_info, "vpnName");
	if (!vpnNameJson) {
		cJSON_Delete(data_info);
		return -3;
	}
    
	int depth = 1;
	char filepath[1024] = {0};
	int i, ret = -1;
	int len = trave_dir(filename, depth);
	char *Right_file = NULL;

    if (strlen(vpnNameJson->valuestring) == 0) {
		for (i = 0; i < len; i++) {
			if (strstr(filename[i], ".ovpn")) {
				snprintf(filepath, sizeof(filepath), "%s/%s", g_vpn_file_dir, filename[i]);

				FILE *data_file = fopen(filepath, "r");
				if (data_file) {
					fseek(data_file, 0, SEEK_END);
					size_t size = ftell(data_file);
					rewind(data_file);

					VLA(uint8_t, data, size);

					if (fread(data, sizeof(uint8_t), size, data_file) != size) {
						DEBUG_PRINT(DEBUG_LEVEL_ERROR, "read error in processSendVpnFileRequest");
						cJSON_Delete(data_info);
						fclose(data_file);
						return -1;
					}

					if (fclose(data_file) < 0) {
						DEBUG_PRINT(DEBUG_LEVEL_ERROR, "close error in processSendVpnFileRequest");
						cJSON_Delete(data_info);
						return -2;
					}
                    
					int count = size / ( MAX_SEND_DATA_SIZE );
					char fileData[MAX_SEND_DATA_SIZE];
					
                    for (i = 0; i <= count; i++) {
						if (i == count) {
							cJSON *fileJson = cJSON_CreateObject();
							if (!fileJson) {
								cJSON_Delete(data_info);
								return -3;
							}
                            
							cJSON *dataJson = cJSON_CreateObject();
							if (!dataJson) {
								cJSON_Delete(data_info);
								cJSON_Delete(fileJson);
								return -4;
							}
                            
							memset(fileData, 0x00, MAX_SEND_DATA_SIZE);
							memcpy(fileData, &data[i * MAX_SEND_DATA_SIZE], size - count * MAX_SEND_DATA_SIZE);
                            
							cJSON_AddStringToObject(fileJson, "type", sendVpnFileRsp);
							cJSON_AddStringToObject(dataJson, "vpnfileName", filepath);
							cJSON_AddNumberToObject(dataJson, "status", 1);
							cJSON_AddStringToObject(dataJson, "fileData", fileData);

                            char *data = cJSON_PrintUnformatted(dataJson);
							cJSON_AddStringToObject(fileJson, "data", data);
                            free(data);
                            
							char *Rsp = cJSON_Print(fileJson);
							if (!Rsp) {
								cJSON_Delete(data_info);
								cJSON_Delete(fileJson);
								return -1;
							}
                            
							if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
                                (uint8_t *)Rsp, strlen(Rsp), NULL) < 1) {
								cJSON_Delete(data_info);
								cJSON_Delete(fileJson);
                                free(Rsp);
								return -1;
							}

                            free(Rsp);
							cJSON_Delete(fileJson);
						} else {
							cJSON *fileJson = cJSON_CreateObject();
							if (!fileJson) {
								cJSON_Delete(fileJson);
								cJSON_Delete(data_info);
								return -3;
							}
                            
							cJSON *dataJson = cJSON_CreateObject();
							if (!dataJson) {
								cJSON_Delete(fileJson);
								cJSON_Delete(data_info);
								return -4;
							}
                            
							memset(fileData, 0x00, MAX_SEND_DATA_SIZE);
							memcpy(fileData, &data[i * MAX_SEND_DATA_SIZE], MAX_SEND_DATA_SIZE);
                            
							cJSON_AddStringToObject(fileJson, "type", sendVpnFileRsp);
							cJSON_AddStringToObject(dataJson, "vpnfileName", filepath);
							cJSON_AddNumberToObject(dataJson, "status", 0);
							cJSON_AddStringToObject(dataJson, "fileData", fileData);

                            char *data = cJSON_PrintUnformatted(dataJson);
							cJSON_AddStringToObject(fileJson, "data", data);
                            free(data);
                            
							char *Rsp = cJSON_Print(fileJson);
							if (!Rsp) {
								cJSON_Delete(fileJson);
								cJSON_Delete(data_info);
								return -1;
							}
                            
							if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
                                (uint8_t *)Rsp, strlen(Rsp), NULL) < 1) {
								cJSON_Delete(fileJson);
								cJSON_Delete(data_info);
                                free(Rsp);
								return -1;
							}

                            free(Rsp);
							cJSON_Delete(fileJson);
						}
					}
                    
					DEBUG_PRINT(DEBUG_LEVEL_INFO, "file %s send complete\n", filepath);
				}
			}
		}
	} else {
		if (strlen(assetInfo)) {
			cJSON *curAsset = cJSON_Parse(assetInfo);
			if (!curAsset) {
				cJSON_Delete(data_info);
				return -4;
			}
            
			cJSON *dataJson = cJSON_CreateObject();
			if (dataJson) {
				cJSON_Delete(curAsset);
				cJSON_Delete(data_info);
				return -4;
			}
            
			cJSON *pJsonArry = cJSON_GetObjectItem(curAsset, "VPNINFO");
			int vpnAssetSize = 0, i = 0;

            if (!pJsonArry) {
				cJSON_Delete(data_info);
				cJSON_Delete(curAsset);
				return -5;
			}
            
			vpnAssetSize = cJSON_GetArraySize(pJsonArry);
			for (i = 0; i < vpnAssetSize; i++) {
				cJSON *object = cJSON_GetArrayItem(pJsonArry, i);
				if (object) {
					cJSON *item = cJSON_GetObjectItem(object, "vpnName");
					if (item) {
						if (!strcmp(vpnNameJson->valuestring, item->valuestring)) {
							cJSON *vpnfileNameJson = cJSON_GetObjectItem(object, "vpnfileName");
							if (!vpnfileNameJson) {
								cJSON_Delete(data_info);
								cJSON_Delete(curAsset);
								return -6;
							}
                            
							Right_file = vpnfileNameJson->valuestring;
							if (!Right_file) {
								cJSON_Delete(data_info);
								cJSON_Delete(curAsset);
								return -7;
							}
                            
							break;
						}
					}
				}
			}
            
			if (Right_file) {
				for (i = 0; i < len; i++) {
					if (!strcmp(filename[i], Right_file)) {
						snprintf(filepath, sizeof(filepath), "%s/%s", g_vpn_file_dir, filename[i]);

						if (filepath) {
							ret = Addfilesender(friendnum, filepath);
							break;
						}
					}
				}
                
				for (i = 0; i < len; i++) {
					if (!strcmp(filename[i], Right_file)) {
						snprintf(filepath, sizeof(filepath), "%s/%s", g_vpn_file_dir, filename[i]);
						
						FILE *data_file = fopen(filepath, "r");
						if (data_file) {
							fseek(data_file, 0, SEEK_END);
							size_t size = ftell(data_file);
							rewind(data_file);

							VLA (uint8_t, data, size);

							if (fread(data, sizeof(uint8_t), size, data_file) != size) {
								DEBUG_PRINT(DEBUG_LEVEL_ERROR, "read error in processSendVpnFileRequest");
								cJSON_Delete(data_info);
								fclose(data_file);
								return -1;
							}

							fclose(data_file);
                                
							int count = size / ( MAX_SEND_DATA_SIZE );
							char fileData[MAX_SEND_DATA_SIZE];
                            
							for (i = 0; i <= count; i++) {
								if (i == count) {
									cJSON *fileJson = cJSON_CreateObject();
									if (!fileJson) {
										cJSON_Delete(data_info);
										return -3;
									}
                                    
									cJSON *dataJson = cJSON_CreateObject();
									if (!dataJson) {
										cJSON_Delete(data_info);
										cJSON_Delete(fileJson);
										return -4;
									}
                                    
									memset(fileData, 0x00, MAX_SEND_DATA_SIZE);
									memcpy(fileData, &data[i * MAX_SEND_DATA_SIZE], size-count * MAX_SEND_DATA_SIZE);
									cJSON_AddStringToObject(fileJson, "type", sendVpnFileRsp);
									cJSON_AddStringToObject(dataJson, "vpnfileName", filepath);
									cJSON_AddNumberToObject(dataJson, "status", 1);
									cJSON_AddStringToObject(dataJson, "fileData", fileData);

                                    char *data = cJSON_PrintUnformatted(dataJson);
									cJSON_AddStringToObject(fileJson, "data", data);
                                    free(data);
                                    
									char *Rsp = cJSON_Print(fileJson);
									if (!Rsp) {
										cJSON_Delete(data_info);
										cJSON_Delete(fileJson);
										return -1;
									}
									if (tox_friend_send_message(qlinkNode, friendnum, 
                                        TOX_MESSAGE_TYPE_NORMAL, (uint8_t *)Rsp, strlen(Rsp), NULL) < 1) {
										cJSON_Delete(data_info);
										cJSON_Delete(fileJson);
                                        free(Rsp);
										return -1;
									}

                                    free(Rsp);
									cJSON_Delete ( fileJson );
								} else {
									cJSON *fileJson = cJSON_CreateObject();
									if (!fileJson) {
										cJSON_Delete(fileJson);
										cJSON_Delete(data_info);
										return -3;
									}
                                    
									cJSON *dataJson = cJSON_CreateObject();
									if (!dataJson) {
										cJSON_Delete(fileJson);
										cJSON_Delete(data_info);
										return -4;
									}
                                    
									memset(fileData, 0x00, MAX_SEND_DATA_SIZE);
									memcpy(fileData, &data[i * MAX_SEND_DATA_SIZE], MAX_SEND_DATA_SIZE);
									cJSON_AddStringToObject(fileJson, "type", sendVpnFileRsp);
									cJSON_AddStringToObject(dataJson, "vpnfileName", filepath);
									cJSON_AddNumberToObject(dataJson, "status", 0);
									cJSON_AddStringToObject(dataJson, "fileData", fileData);

                                    char *data = cJSON_PrintUnformatted(dataJson);
									cJSON_AddStringToObject(fileJson, "data", data);
                                    free(data);
                                    
									char *Rsp = cJSON_Print(fileJson);
									if (!Rsp) {
										cJSON_Delete(fileJson);
										cJSON_Delete(data_info);
										return -1;
									}
                                    
									if (tox_friend_send_message(qlinkNode, friendnum, 
                                        TOX_MESSAGE_TYPE_NORMAL, (uint8_t *)Rsp, strlen(Rsp), NULL) < 1) {
										cJSON_Delete(fileJson);
										cJSON_Delete(data_info);
                                        free(Rsp);
										return -1;
									}

                                    free(Rsp);
									cJSON_Delete ( fileJson );
								}
							}
                            
							DEBUG_PRINT(DEBUG_LEVEL_INFO, "file %s send complete\n", filepath);
						}
					}
				}
			}
            
			cJSON_Delete(curAsset);
		}
	}
    
	char *Rsp = "{\"type\":\"sendVpnFileRsp\"}";
	if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
        (uint8_t *)Rsp, strlen(Rsp), NULL) < 1) {
		return -1;
	} else {
		DEBUG_PRINT(DEBUG_LEVEL_INFO, "send .ovpn complete");
	}
    
	cJSON_Delete ( data_info );
	return 0;
}

int processVpnUserPassAndPrivateKeyReq(cJSON *pJson, int friendnum)
{
	if (!pJson) {
		return -1;
	}
    
	cJSON *data_info = cJSON_GetObjectItem(pJson, "data");
	if (!data_info) {
		return -2;
	}
    
	data_info = cJSON_Parse(data_info->valuestring);
	if (!data_info) {
		return -2;
	}
    
	cJSON *vpnNameJson = cJSON_GetObjectItem(data_info, "vpnName");
	if (!vpnNameJson) {
		cJSON_Delete(data_info);
		return -3;
	}
    
	if (strlen(assetInfo)) {
		cJSON *curAsset = cJSON_Parse(assetInfo);
		if (!curAsset) {
			cJSON_Delete(data_info);
			return -4;
		}
        
		cJSON *dataJson = cJSON_CreateObject();
		if (!dataJson) {
			cJSON_Delete(curAsset);
			cJSON_Delete(data_info);
			return -4;
		}
        
		cJSON *vpnuserpassandprivatekeyRspJson = cJSON_CreateObject();
		if (!vpnuserpassandprivatekeyRspJson) {
			cJSON_Delete(curAsset);
			cJSON_Delete(data_info);
			cJSON_Delete(dataJson);
			return -4;
		}

        int vpnAssetSize = 0, i = 0;
        
		cJSON *pJsonArry = cJSON_GetObjectItem(curAsset, "VPNINFO");
        if (!pJsonArry) {
			cJSON_Delete(data_info);
			cJSON_Delete(curAsset);
			cJSON_Delete(vpnuserpassandprivatekeyRspJson);
			return -5;
		}
        
		vpnAssetSize = cJSON_GetArraySize(pJsonArry);
		for (i = 0; i < vpnAssetSize; i++) {
			cJSON *object = cJSON_GetArrayItem(pJsonArry, i);
			if (object) {
				cJSON *item = cJSON_GetObjectItem(object, "vpnName");
				if (item) {
					if (!strcmp(vpnNameJson->valuestring, item->valuestring)) {
						cJSON_AddStringToObject(vpnuserpassandprivatekeyRspJson, "type", vpnUserPassAndPrivateKeyRsp);
						cJSON_AddStringToObject(dataJson, "vpnName", vpnNameJson->valuestring);
						cJSON_AddStringToObject(dataJson, "userName", cJSON_GetObjectItem(object, "userName")->valuestring);
						cJSON_AddStringToObject(dataJson, "password", cJSON_GetObjectItem(object, "password")->valuestring);
						cJSON_AddStringToObject(dataJson, "privateKey", cJSON_GetObjectItem(object, "privateKey")->valuestring);

                        char *data = cJSON_PrintUnformatted(dataJson);
                        cJSON_AddStringToObject(vpnuserpassandprivatekeyRspJson, "data", data);
                        free(data);
                        
						char *Rsp = cJSON_Print(vpnuserpassandprivatekeyRspJson);
						if (!Rsp) {
							cJSON_Delete(data_info);
							cJSON_Delete(curAsset);
							cJSON_Delete(vpnuserpassandprivatekeyRspJson);
							return -5;
						}
                        
						if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
                            (uint8_t *)Rsp, strlen(Rsp), NULL) < 1) {
							DEBUG_PRINT(DEBUG_LEVEL_ERROR, 
                                "could not send VpnUserPassAndPrivateKeyRspJson to friend num %u", friendnum);
						} else {
							DEBUG_PRINT(DEBUG_LEVEL_INFO, "VpnUserPassAndPrivateKeyRspJson: %s\n", Rsp);
						}

                        free(Rsp);
						break;
					}
				}
			}
		}
        
		if (i == vpnAssetSize) {
			char *Rsp = "-1";
			if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
                (uint8_t *)Rsp, strlen(Rsp), NULL ) < 1) {
				DEBUG_PRINT(DEBUG_LEVEL_ERROR, 
                    "could not send VpnUserPassAndPrivateKeyRspJson to friend num %u", friendnum);
				cJSON_Delete(data_info);
				cJSON_Delete(curAsset);
				cJSON_Delete(vpnuserpassandprivatekeyRspJson);
				return -7;
			} else {
				DEBUG_PRINT(DEBUG_LEVEL_INFO, "VpnUserPassAndPrivateKeyRspJson: %s", Rsp);
			}
		}
        
		cJSON_Delete(curAsset);
		cJSON_Delete(vpnuserpassandprivatekeyRspJson);
	} else {
		char *Rsp = "-1";
		if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
            (uint8_t *)Rsp, strlen(Rsp), NULL ) < 1) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, 
                "could not send VpnUserPassAndPrivateKeyRspJson to friend num %u", friendnum);
		} else {
			DEBUG_PRINT(DEBUG_LEVEL_INFO, "VpnUserPassAndPrivateKeyRspJson: %s", Rsp);
		}
	}
    
	cJSON_Delete(data_info);
	return 0;
}

int processVpnUserPassAndPrivateKeyRsp(cJSON *pJson, int friendnum)
{
	if (!pJson) {
		return -1;
	}
    
	cJSON *data_info = cJSON_GetObjectItem(pJson, "data");
	if (!data_info) {
		return -2;
	}
    
	data_info = cJSON_Parse(data_info->valuestring);
	if (!data_info) {
		return -3;
	}
    
	cJSON *vpnNameJson = cJSON_GetObjectItem(data_info, "vpnName");
	if (!vpnNameJson) {
		return -4;
	}
    
	cJSON *userNameJson = cJSON_GetObjectItem(data_info, "userName");
	if (!userNameJson) {
		return -5;
	}
    
	cJSON *passwordJson = cJSON_GetObjectItem(data_info, "password");
	if (!passwordJson) {
		return -6;
	}
    
	cJSON *privateKeyJson = cJSON_GetObjectItem(data_info, "privateKey");
	if  ( NULL == privateKeyJson )
	{
		return -7;
	}
    
	cJSON *vpnfileNameJson = cJSON_GetObjectItem(data_info, "vpnfileName");
	if (!vpnfileNameJson) {
		return -8;
	}
    
	addvpnAsset(vpnNameJson->valuestring,
        userNameJson->valuestring,
        passwordJson->valuestring,
        privateKeyJson->valuestring,
        vpnfileNameJson->valuestring);
    
	cJSON_Delete(data_info);
	return 0;
}

int processVpnUserAndPasswordReq(cJSON *pJson, int friendnum)
{
	if (!pJson) {
		return -1;
	}
    
	cJSON *data_info = cJSON_GetObjectItem(pJson, "data");
	if (!data_info) {
		return -2;
	}
    
	data_info = cJSON_Parse(data_info->valuestring);
	if (!data_info) {
		return -2;
	}
    
	cJSON *vpnNameJson = cJSON_GetObjectItem(data_info, "vpnName");
	if (!vpnNameJson) {
		return -3;
	}
    
	if (strlen(assetInfo)) {
		cJSON *curAsset = cJSON_Parse(assetInfo);
		if (!curAsset) {
			cJSON_Delete(data_info);
			return -4;
		}
        
		cJSON *dataJson = cJSON_CreateObject();
		if (!dataJson) {
			cJSON_Delete(data_info);
			cJSON_Delete(curAsset);
			return -4;
		}
        
		cJSON *vpnuserandpassRspJson = cJSON_CreateObject();
		if (!vpnuserandpassRspJson) {
			cJSON_Delete(data_info);
			cJSON_Delete(curAsset);
			cJSON_Delete(dataJson);
			return -4;
		}
        
		cJSON *pJsonArry = cJSON_GetObjectItem(curAsset, "VPNINFO");
		int vpnAssetSize = 0, i = 0;
		if (!pJsonArry) {
			cJSON_Delete(data_info);
			cJSON_Delete(curAsset);
			cJSON_Delete(dataJson);
			return -5;
		}
        
		vpnAssetSize = cJSON_GetArraySize(pJsonArry);
		for (i = 0; i < vpnAssetSize; i++) {
			cJSON *object = cJSON_GetArrayItem(pJsonArry, i);
			if (object) {
				cJSON *item = cJSON_GetObjectItem(object, "vpnName");
				if (item) {
					if (!strcmp(vpnNameJson->valuestring, item->valuestring)) {
						cJSON_AddStringToObject(vpnuserandpassRspJson, "type", vpnUserAndPasswordRsp);
						cJSON_AddStringToObject(dataJson, "vpnName", vpnNameJson->valuestring);
						cJSON_AddStringToObject(dataJson, "userName", cJSON_GetObjectItem(object,"userName")->valuestring);
						cJSON_AddStringToObject(dataJson, "password", cJSON_GetObjectItem(object,"password")->valuestring);

                        char *data = cJSON_PrintUnformatted(dataJson);
                        cJSON_AddStringToObject(vpnuserandpassRspJson, "data", data);
                        free(data);
                        
						char *Rsp = cJSON_Print(vpnuserandpassRspJson);
						if (!Rsp) {
							cJSON_Delete(data_info);
							cJSON_Delete(curAsset);
							cJSON_Delete(dataJson);
							return -5;
						}
                        
						if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
                            (uint8_t *)Rsp, strlen(Rsp), NULL ) < 1) {
							DEBUG_PRINT(DEBUG_LEVEL_ERROR, "could not send vpnuserandpassRspJson to friend num %u", friendnum );
						} else {
							DEBUG_PRINT(DEBUG_LEVEL_INFO, "vpnuserandpassRspJson: %s", Rsp);
						}

                        free(Rsp);
						break;
					}
				}
			}
		}
        
		if (i == vpnAssetSize) {
			char *Rsp = "-1";
			if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
                (uint8_t *)Rsp, strlen(Rsp), NULL) < 1) {
				DEBUG_PRINT(DEBUG_LEVEL_ERROR,"could not send vpnuserandpassRspJson to friend num %u", friendnum);
			} else {
				DEBUG_PRINT(DEBUG_LEVEL_INFO,"vpnuserandpassRspJson: %s", Rsp);
			}
		}
        
		cJSON_Delete(curAsset);
		cJSON_Delete(vpnuserandpassRspJson);
	} else {
		char *Rsp = "-1";
		if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
            (uint8_t *)Rsp, strlen(Rsp), NULL) < 1) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "could not send vpnuserandpassRspJson to friend num %u", friendnum);
		} else {
			DEBUG_PRINT(DEBUG_LEVEL_INFO, "vpnuserandpassRspJson: %s", Rsp);
		}
	}
    
	cJSON_Delete(data_info);
	return 0;
}

int processVpnUserAndPasswordRsp(cJSON *pJson, int friendnum)
{
	if (!pJson) {
		return -1;
	}
    
	cJSON *data_info = cJSON_GetObjectItem(pJson, "data");
	if (!data_info) {
		return -2;
	}
    
	data_info = cJSON_Parse(data_info->valuestring);
	if (!data_info) {
		return -2;
	}
    
	cJSON *vpnNameJson = cJSON_GetObjectItem(data_info, "vpnName");
	if (!vpnNameJson ) {
		return -3;
	}
    
	cJSON *userNameJson = cJSON_GetObjectItem(data_info, "userName");
	if (!userNameJson ) {
		return -4;
	}
    
	cJSON *passwordJson = cJSON_GetObjectItem(data_info, "password");
	if (!passwordJson ) {
		return -5;
	}
    
	addvpnAsset(vpnNameJson->valuestring,
        userNameJson->valuestring,
        passwordJson->valuestring,
        "", "");
    
	cJSON_Delete(data_info);
	return 0;
}

int processVpnPrivateKeyReq(cJSON *pJson, int friendnum)
{
	if (!pJson) {
		return -1;
	}
    
	cJSON *data_info = cJSON_GetObjectItem(pJson, "data");
	if (!data_info) {
		return -2;
	}
    
	data_info = cJSON_Parse(data_info->valuestring);
	if (!data_info) {
		return -2;
	}
    
	cJSON *vpnNameJson = cJSON_GetObjectItem(data_info, "vpnName");
	if (!vpnNameJson) {
		return -3;
	}
    
	if (strlen(assetInfo)) {
		cJSON *curAsset = cJSON_Parse(assetInfo);
		if (!curAsset) {
			cJSON_Delete(data_info);
			return -4;
		}
        
		cJSON *dataJson = cJSON_CreateObject();
		if (!dataJson) {
			cJSON_Delete(data_info);
			cJSON_Delete(curAsset);
			return -4;
		}
        
		cJSON *vpnprivateKeyRspJson = cJSON_CreateObject();
		if (!vpnprivateKeyRspJson) {
			cJSON_Delete(data_info);
			cJSON_Delete(curAsset);
			cJSON_Delete(dataJson);
			return -4;
		}
        
		cJSON *pJsonArry = cJSON_GetObjectItem(curAsset, "VPNINFO");
		int vpnAssetSize = 0, i = 0;
		if (!pJsonArry) {
			cJSON_Delete(data_info);
			cJSON_Delete(curAsset);
			cJSON_Delete(dataJson);
			return -5;
		}
        
		vpnAssetSize = cJSON_GetArraySize(pJsonArry);
		for (i = 0; i < vpnAssetSize; i++) {
			cJSON *object = cJSON_GetArrayItem(pJsonArry, i);
			if (object) {
				cJSON *item = cJSON_GetObjectItem(object, "vpnName");
				if (item) {
					if (!strcmp(vpnNameJson->valuestring,item->valuestring)) {
						cJSON_AddStringToObject(vpnprivateKeyRspJson, "type", vpnPrivateKeyRsp);
						cJSON_AddStringToObject(dataJson, "vpnName", vpnNameJson->valuestring);
						cJSON_AddStringToObject(dataJson, "privateKey", cJSON_GetObjectItem(object, "privateKey")->valuestring);
                            
                        char *data = cJSON_PrintUnformatted(dataJson);
                        cJSON_AddStringToObject(vpnprivateKeyRspJson, "data", data);
                        free(data);
                        
						char *Rsp = cJSON_Print(vpnprivateKeyRspJson);
						if (!Rsp) {
							cJSON_Delete(data_info);
							cJSON_Delete(curAsset);
							cJSON_Delete(dataJson);
							return -5;
						}
                        
						if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
                            (uint8_t *)Rsp, strlen(Rsp), NULL) < 1) {
							DEBUG_PRINT(DEBUG_LEVEL_ERROR,
                                "could not send vpnprivateKeyRspJson to friend num %u", friendnum);
						} else {
							DEBUG_PRINT(DEBUG_LEVEL_INFO,"vpnprivateKeyRspJson: %s", Rsp);
						}

                        free(Rsp);
						break;
					}
				}
			}
		}
        
		if (i == vpnAssetSize) {
			char *Rsp = "-1";
			if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
                (uint8_t *)Rsp, strlen(Rsp), NULL ) < 1) {
				DEBUG_PRINT(DEBUG_LEVEL_ERROR, 
                    "could not send vpnprivateKeyRspJson to friend num %u", friendnum);
			} else {
				DEBUG_PRINT(DEBUG_LEVEL_INFO, "vpnprivateKeyRspJson: %s", Rsp);
			}
		}
        
		cJSON_Delete(curAsset);
		cJSON_Delete(vpnprivateKeyRspJson);
	} else {
		char *Rsp = "-1";
		if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
            (uint8_t *)Rsp, strlen(Rsp), NULL) < 1) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR,"could not send vpnprivateKeyRspJson to friend num %u", friendnum);
		} else {
			DEBUG_PRINT(DEBUG_LEVEL_INFO,"vpnprivateKeyRspJson: %s", Rsp);
		}
	}
    
	cJSON_Delete(data_info);
	return 0;
}

int processVpnPrivateKeyRsp(cJSON *pJson, int friendnum)
{
	if (!pJson) {
		return -1;
	}
    
	cJSON *data_info = cJSON_GetObjectItem(pJson, "data");
	if (!data_info) {
		return -1;
	}
    
	data_info = cJSON_Parse(data_info->valuestring);
	if (!data_info) {
		return -1;
	}
    
	cJSON *vpnNameJson = cJSON_GetObjectItem(data_info, "vpnName");
	if (!vpnNameJson) {
		return -1;
	}
    
	cJSON *privateJson = cJSON_GetObjectItem(data_info, "privateKey");
    if (!privateJson) {
		return -1;
	}
    
	addvpnAsset(vpnNameJson->valuestring,
        "", "", privateJson->valuestring, "");
    
	cJSON_Delete(data_info);
	return 0;
}

int processJoinGroupChatReq(cJSON *pJson, int friendnum)
{
	if (qlinkNode) {
		return -1;
	}

    if (friend_not_valid_Qlink(qlinkNode, friendnum)) {
		return -3;
	}
    
	if (!pJson) {
		return -4;
	}
    
	cJSON *data_info = cJSON_GetObjectItem(pJson, "data");
	if (!data_info) {
		return -5;
	}
    
	data_info = cJSON_Parse(data_info->valuestring);
	if (!data_info) {
		return -5;
	}
    
	cJSON *assetNameJson = cJSON_GetObjectItem(data_info, "assetName");
	if (!assetNameJson) {
		cJSON_Delete(data_info);
		return -6;
	}
    
	if (strlen(assetInfo)) {
		cJSON *curAsset = cJSON_Parse(assetInfo);
		if (!curAsset) {
			cJSON_Delete(data_info);
			return -7;
		}
        
		cJSON *pJsonArry = cJSON_GetObjectItem(curAsset, "VPNINFO");
		if (!pJsonArry) {
			cJSON_Delete(data_info);
			cJSON_Delete(curAsset);
			return -7;
		}
        
		int vpnAssetSize = 0, i = 0;

		vpnAssetSize = cJSON_GetArraySize(pJsonArry);
		for (i = 0; i < vpnAssetSize; i++) {
			cJSON *object = cJSON_GetArrayItem(pJsonArry, i);
			if (object) {
				cJSON *item = cJSON_GetObjectItem(object, "vpnName");
				if (item) {
					if (!strcmp(assetNameJson->valuestring,item->valuestring)) {
						cJSON *groupnum = cJSON_GetObjectItem(object, "Groupnum");
						bool IsInviteOK = tox_conference_invite(qlinkNode, friendnum, groupnum->valueint, NULL);
						if (IsInviteOK == false) {
							DEBUG_PRINT(DEBUG_LEVEL_ERROR,"Invite %u friend to group chat fail", friendnum);
						} else {
							DEBUG_PRINT(DEBUG_LEVEL_INFO,"Invite %u friend to group chat success", friendnum);
						}
                        
						break;
					}
				}
			}
		}
        
		if (i == vpnAssetSize) {
			char *Rsp = "-1";
			if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
                (uint8_t *)Rsp, strlen(Rsp), NULL) < 1) {
				DEBUG_PRINT(DEBUG_LEVEL_ERROR,"group is not exit,send fail");
			} else {
				DEBUG_PRINT(DEBUG_LEVEL_INFO,"group is not exit,send success");
			}
		}
        
		cJSON_Delete(curAsset);
	} else {
		cJSON_Delete(data_info);
		return -2;
	}
    
	cJSON_Delete (data_info);
    return 0;
}

int processRecordSaveReq(cJSON *pJson, int friendnum)
{
	if (!pJson) {
		return -1;
	}
    
	cJSON *data_info = cJSON_GetObjectItem(pJson, "data");
	if (!data_info) {
		return -2;
	}
    
	data_info = cJSON_Parse(data_info->valuestring);
	if (!data_info) {
		return -2;
	}
    
	cJSON *txidJson = cJSON_GetObjectItem(data_info, "txid");
	cJSON *appVersionJson = cJSON_GetObjectItem(data_info, "appVersion");
	if (!txidJson || !appVersionJson) {
		cJSON_Delete(data_info);
		return -3;
	}
    
	cJSON *RecordSaveRspJson = cJSON_CreateObject();
	if (!RecordSaveRspJson) {
		cJSON_Delete(data_info);
		return -4;
	}
    
	cJSON *item = cJSON_CreateObject();
	if (!item){
		cJSON_Delete(data_info);
		cJSON_Delete(RecordSaveRspJson);
	}
    
	cJSON_AddStringToObject(RecordSaveRspJson, "type",recordSaveRsp);
	cJSON_AddItemToObject(RecordSaveRspJson, "data", item);
	cJSON_AddStringToObject(item, "txid", txidJson->valuestring);
	cJSON_AddStringToObject(item, "appVersion", appVersionJson->valuestring);
	cJSON_AddStringToObject(item, "success", "1");

	char *RecordSaveRsp = cJSON_Print(RecordSaveRspJson);
	if (!RecordSaveRsp) {
		cJSON_Delete(data_info);
		cJSON_Delete(RecordSaveRspJson);
		return -4;
	}
    
	if (tox_friend_send_message(qlinkNode, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
        (uint8_t *)RecordSaveRsp, strlen(RecordSaveRsp), NULL) < 1) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "could not send RecordSaveRsp to friend num %u", friendnum);
	} else {
		DEBUG_PRINT(DEBUG_LEVEL_INFO, "success send RecordSaveRsp");
	}

    free(RecordSaveRsp);
	cJSON_Delete(data_info);
	cJSON_Delete(RecordSaveRspJson);
	return 0;
}

/*****************************************************************************
 函 数 名  : processSendVpnFileListReq
 功能描述  : 处理文件列表请求消息
 输入参数  : cJSON *pJson   
             int friendnum  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月19日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int processSendVpnFileListReq(cJSON *pJson, int friendnum)
{
    char *filelist = NULL;
    unsigned int buflen = 0;
	int i;
	int len = 0;
    char *md5 = NULL;
    char msg[MAX_SEND_DATA_SIZE + 1] = {0};
    struct tox_msg_send *tmsg = NULL;
    int first = 1;
    
	if (!pJson) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pJson null");
        return -1;
    }
    
	cJSON *dataInfo = cJSON_GetObjectItem(pJson, "data");
	if (!dataInfo) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "parse data fail");
		return -1;
    }

	cJSON *appVersionJson = cJSON_GetObjectItem(dataInfo, "appVersion");
	if (!appVersionJson) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "parse app version fail");
		return -1;
    }
    
	cJSON *RspJson = cJSON_CreateObject();
	if (!RspJson) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "create json obj fail");
		return -1;
    }

	cJSON *item = cJSON_CreateObject();
	if (!item) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "create json obj fail");
		cJSON_Delete(RspJson);
        return -1;
	}

    memset(filename, 0, sizeof(filename));
	len = trave_dir(filename, 1);

    buflen = 1024;
    filelist = calloc(1, buflen);
    if (!filelist) {
        cJSON_Delete(RspJson);
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "calloc err![%d]", errno);
        return -1;
    }

    for (i = 0; i < len; i++) {
		if (strstr(filename[i], ".ovpn")) {
            if (strlen(filename[i]) >= buflen - strlen(filelist)) {
                buflen += 1024;
                filelist = realloc(filelist, buflen);
                if (!filelist) {
                    cJSON_Delete(RspJson);
                    free(filelist);
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR, "realloc err![%d]", errno);
                    return -1;
                }
            }

            if (first) {
                snprintf(filelist, buflen - strlen(filelist), "%s", filename[i]);
                first = 0;
            } else {
                snprintf(filelist + strlen(filelist), buflen - strlen(filelist), ";%s", filename[i]);
            }
		}
	}

    buflen = strlen(filelist);
    md5 = md5_hash((unsigned char *)filelist, buflen);
        
	cJSON_AddStringToObject(RspJson, "type", sendVpnFileListRsp);
	cJSON_AddItemToObject(RspJson, "data", item);
	cJSON_AddNumberToObject(item, "msgid", g_tox_msgid);
	cJSON_AddStringToObject(item, "appVersion", appVersionJson->valuestring);
	cJSON_AddNumberToObject(item, "msglen", buflen);
    cJSON_AddStringToObject(item, "md5", md5);

    char *frame = cJSON_PrintUnformatted(RspJson);
    if (!frame) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "json print err!");
		cJSON_Delete(RspJson);
		return -1;
	}

    if (buflen > MAX_SEND_DATA_SIZE) {
        cJSON_AddNumberToObject(item, "more", 0);
        cJSON_AddNumberToObject(item, "offset", 0);

        memcpy(msg, filelist, MAX_SEND_DATA_SIZE);
        cJSON_AddStringToObject(item, "msg", msg);
    } else {
        cJSON_AddNumberToObject(item, "more", 0);
        cJSON_AddNumberToObject(item, "offset", 0);
        cJSON_AddStringToObject(item, "msg", filelist);
    }
    
	char *RspStr = cJSON_PrintUnformatted(RspJson);
	if (!RspStr) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "json print err!");
		cJSON_Delete(RspJson);
        free(frame);
		return -1;
	}

    tmsg = (struct tox_msg_send *)calloc(1, sizeof(*tmsg));
    if (!tmsg) {
        cJSON_Delete(RspJson);
        free(RspStr);
        free(frame);
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "calloc err![%d]", errno);
    	return -1;
    }

    tmsg->msg = filelist;
    tmsg->msgid = g_tox_msgid;
    tmsg->friendnum = friendnum;
    tmsg->msglen = buflen;
    strncpy(tmsg->frame, frame, sizeof(tmsg->frame) - 1);
    strncpy(tmsg->bufmsg, RspStr, sizeof(tmsg->bufmsg) - 1);

    pthread_rwlock_wrlock(&g_tox_msg_send_lock);
    list_add_tail(&tmsg->list, &g_tox_msg_send_list);
    g_tox_msgid++;
    pthread_rwlock_unlock(&g_tox_msg_send_lock);
        
	cJSON_Delete(RspJson);
    free(RspStr);
    free(frame);
	return 0;
}

/*****************************************************************************
 函 数 名  : processSendVpnFileListRsp
 功能描述  : 文件列表消息回复
 输入参数  : cJSON *pJson   
             int friendnum  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月19日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int processSendVpnFileListRsp(cJSON *pJson, int friendnum)
{
    struct tox_msg_send *pos = NULL;
    struct tox_msg_send *n = NULL;
    char msg[MAX_SEND_DATA_SIZE + 1] = {0};
    int more = 0;
    
    if (!pJson) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pjson null");
        return -1;
    }
    
	cJSON *dataInfo = cJSON_GetObjectItem(pJson, "data");
	if (!dataInfo) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pjson get data fail");
		return -1;
    }

    cJSON *msgid = cJSON_GetObjectItem(dataInfo, "msgid");
	if (!msgid) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pjson get msgid fail");
		return -1;
    }

    cJSON *offset = cJSON_GetObjectItem(dataInfo, "offset");
	if (!offset) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pjson get offset fail");
		return -1;
    }

    pthread_rwlock_wrlock(&g_tox_msg_send_lock);
    list_for_each_entry_safe(pos, n, &g_tox_msg_send_list, list) {
        if (pos->msgid == msgid->valueint && pos->offset == offset->valueint) {
            if (!pos->msg) {
                list_del(&pos->list);
                free(pos);
                break;
            }

            pos->offset += MAX_SEND_DATA_SIZE;

            /* send all bytes */
            if (pos->msglen - pos->offset <= 0) {
                list_del(&pos->list);
                free(pos->msg);
                free(pos);
                break;
            }

            if (pos->msglen - pos->offset > MAX_SEND_DATA_SIZE) {
                memcpy(msg, pos->msg + pos->offset, MAX_SEND_DATA_SIZE);
                more = 1;
            } else {
                memcpy(msg, pos->msg + pos->offset, pos->msglen - pos->offset);
            }

            cJSON *RspJson = cJSON_Parse(pos->frame);
            if (!RspJson) {
                list_del(&pos->list);
                free(pos->msg);
                free(pos);
                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "parse json err(%s)", pos->frame);
                break;
            }

            cJSON *RspJsonData = cJSON_GetObjectItem(RspJson, "data");
            if (!RspJsonData) {
                list_del(&pos->list);
                free(pos->msg);
                free(pos);
                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "parse json err(%s)", pos->frame);
                break;
            }

            cJSON_AddStringToObject(RspJsonData, "msg", msg);
            cJSON_AddNumberToObject(RspJsonData, "more", more);
            cJSON_AddNumberToObject(RspJsonData, "offset", pos->offset);

            char *RspStr = cJSON_PrintUnformatted(RspJson);
            if (!RspStr) {
                list_del(&pos->list);
                free(pos->msg);
                free(pos);
                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "print json err(%s)", pos->frame);
                break;
            }

            memset(pos->bufmsg, 0, sizeof(pos->bufmsg));
            memcpy(pos->bufmsg, RspStr, strlen(RspStr));
            pos->sendtimes = 0;
            pos->lastsendtime = 0;

            cJSON_Delete(RspJson);
            free(RspStr);
        }
    }
    pthread_rwlock_unlock(&g_tox_msg_send_lock);
    return 0;
}

/*****************************************************************************
 函 数 名  : processSendVpnFileNewRsq
 功能描述  : 请求发送vpn配置文件消息
 输入参数  : cJSON *pJson   
             int friendnum  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月19日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int processSendVpnFileNewReq(cJSON *pJson, int friendnum)
{
    int len = 0;
    char msg[MAX_SEND_DATA_SIZE + 1] = {0};
    struct tox_msg_send *tmsg = NULL;
    char filePath[1024] = {0};
    char *data = NULL;
    
    if (!pJson) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pjson null");
        return -1;
    }
    
	cJSON *dataInfo = cJSON_GetObjectItem(pJson, "data");
	if (!dataInfo) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "json get data fail");
		return -1;
    }

	cJSON *appVersionJson = cJSON_GetObjectItem(dataInfo, "appVersion");
	if (!appVersionJson) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "json get app version fail");
		return -1;
    }

    cJSON *vpnName = cJSON_GetObjectItem(dataInfo, "vpnName");
	if (!vpnName) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "json get vpnname fail");
		return -1;
    }

    cJSON *regist = cJSON_GetObjectItem(dataInfo, "register");
	if (!regist) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "json get register fail");
		return -1;
    }

    if (regist->valueint) {
		snprintf(filePath, sizeof(filePath), "%s/%s", g_vpn_file_dir, vpnName->valuestring);
    } else {
        if (strlen(assetInfo)) {
    		cJSON *curAsset = cJSON_Parse(assetInfo);
    		if (!curAsset) {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "parse json(%s) fail", assetInfo);
    			return -1;
            }
            
    		cJSON *dataJson = cJSON_CreateObject();
    		if (!dataJson) {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "create json obj fail");
    			cJSON_Delete(curAsset);
    			return -1;
    		}
            
    		cJSON *pJsonArry = cJSON_GetObjectItem(curAsset, "VPNINFO");
    		if (!pJsonArry) {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get vpn info fail");
    			cJSON_Delete(curAsset);
    			return -1;
    		}

            int vpnAssetSize = 0, i = 0;
            char *vpnFileName = NULL;
    		vpnAssetSize = cJSON_GetArraySize(pJsonArry);

            for (i = 0; i < vpnAssetSize; i++) {
    			cJSON *object = cJSON_GetArrayItem(pJsonArry, i);
    			if (object) {
    				cJSON *item = cJSON_GetObjectItem(object, "vpnName");
    				if (item) {
    					if (!strcmp(vpnName->valuestring, item->valuestring)) {
    						cJSON *vpnfileNameJson = cJSON_GetObjectItem(object, "vpnfileName");
    						if (!vpnfileNameJson) {
                                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get vpn filename fail");
    							cJSON_Delete(curAsset);
    							return -1;
    						}
                            
    						vpnFileName = vpnfileNameJson->valuestring;
    						DEBUG_PRINT(DEBUG_LEVEL_INFO, "vpn filename:%s", vpnFileName);
    						if (!vpnFileName) {
                                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "vpn filename null");
    							cJSON_Delete(curAsset);
    							return -1;
    						}
                            
    						break;
    					}
    				}
    			}
    		}

            if (!vpnFileName) {
                cJSON_Delete(curAsset);
                return -1;
            }

			snprintf(filePath, sizeof(filePath), "%s/%s", g_vpn_file_dir, vpnFileName);
            cJSON_Delete(curAsset);
    	}
    }

    FILE *dataFile = fopen(filePath, "r");
    if (dataFile) {
    	fseek(dataFile, 0, SEEK_END);
    	size_t size = ftell(dataFile);
    	rewind(dataFile);

        data = calloc(1, size);
        if (!data) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "calloc error(%d)", errno);
    		fclose(dataFile);
    		return -1;
        }
        
    	if (fread(data, sizeof(uint8_t), size, dataFile) != size) {
    		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "read error(%d)", errno);
    		fclose(dataFile);
    		return -1;
    	}

    	fclose(dataFile);

        char *datab64 = base64_encode(data, size);
        free(data);

        cJSON *RspJson = cJSON_CreateObject();
    	if (!RspJson) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "create json obj fail");
    		return -1;
        }

    	cJSON *item = cJSON_CreateObject();
    	if (!item) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "create json obj fail");
    		cJSON_Delete(RspJson);
            return -1;
    	}

        int buflen = strlen(datab64);
        char *md5 = md5_hash((unsigned char *)datab64, buflen);
            
    	cJSON_AddStringToObject(RspJson, "type", sendVpnFileNewRsp);
    	cJSON_AddItemToObject(RspJson, "data", item);
    	cJSON_AddNumberToObject(item, "msgid", g_tox_msgid);
    	cJSON_AddStringToObject(item, "appVersion", appVersionJson->valuestring);
    	cJSON_AddNumberToObject(item, "msglen", buflen);
        cJSON_AddStringToObject(item, "md5", md5);
        cJSON_AddNumberToObject(item, "register", regist->valueint);

        char *frame = cJSON_PrintUnformatted(RspJson);
        if (!frame) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "print json fail");
    		cJSON_Delete(RspJson);
    		return -1;
    	}

        if (buflen > MAX_SEND_DATA_SIZE) {
            cJSON_AddNumberToObject(item, "more", 0);
            cJSON_AddNumberToObject(item, "offset", 0);

            memcpy(msg, datab64, MAX_SEND_DATA_SIZE);
            cJSON_AddStringToObject(item, "msg", msg);
        } else {
            cJSON_AddNumberToObject(item, "more", 0);
            cJSON_AddNumberToObject(item, "offset", 0);
            cJSON_AddStringToObject(item, "msg", datab64);
        }
        
    	char *RspStr = cJSON_PrintUnformatted(RspJson);
    	if (!RspStr) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "print json fail");
    		cJSON_Delete(RspJson);
            free(frame);
    		return -1;
    	}

        tmsg = (struct tox_msg_send *)calloc(1, sizeof(*tmsg));
        if (!tmsg) {
            cJSON_Delete(RspJson);
            free(RspStr);
            free(frame);
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "calloc err![%d]", errno);
        	return -1;
        }

        tmsg->msg = datab64;
        tmsg->msgid = g_tox_msgid;
        tmsg->friendnum = friendnum;
        tmsg->msglen = buflen;
        strncpy(tmsg->frame, frame, sizeof(tmsg->frame) - 1);
        strncpy(tmsg->bufmsg, RspStr, sizeof(tmsg->bufmsg) - 1);

        pthread_rwlock_wrlock(&g_tox_msg_send_lock);
        list_add_tail(&tmsg->list, &g_tox_msg_send_list);
        g_tox_msgid++;
        pthread_rwlock_unlock(&g_tox_msg_send_lock);
            
    	cJSON_Delete(RspJson);
        free(RspStr);
    }
    
    return 0;
}

/*****************************************************************************
 函 数 名  : processSendVpnFileNewRsp
 功能描述  : 回复发送VPN配置文件消息
 输入参数  : cJSON *pJson   
             int friendnum  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月19日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int processSendVpnFileNewRsp(cJSON *pJson, int friendnum)
{
    struct tox_msg_send *pos = NULL;
    struct tox_msg_send *n = NULL;
    char msg[MAX_SEND_DATA_SIZE + 1] = {0};
    int more = 0;
    
    if (!pJson) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pjson null");
        return -1;
    }
    
	cJSON *dataInfo = cJSON_GetObjectItem(pJson, "data");
	if (!dataInfo) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pjson get data fail");
		return -1;
    }

    cJSON *msgid = cJSON_GetObjectItem(dataInfo, "msgid");
	if (!msgid) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pjson get msgid fail");
		return -1;
    }

    cJSON *offset = cJSON_GetObjectItem(dataInfo, "offset");
	if (!msgid) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pjson get offset fail");
		return -1;
    }

    pthread_rwlock_wrlock(&g_tox_msg_send_lock);
    list_for_each_entry_safe(pos, n, &g_tox_msg_send_list, list) {
        if (pos->msgid == msgid->valueint && pos->offset == offset->valueint) {
            if (!pos->msg) {
                list_del(&pos->list);
                free(pos);
                break;
            }

            pos->offset += MAX_SEND_DATA_SIZE;

            /* send all bytes */
            if (pos->msglen - pos->offset <= 0) {
                list_del(&pos->list);
                free(pos->msg);
                free(pos);
                break;
            }

            if (pos->msglen - pos->offset > MAX_SEND_DATA_SIZE) {
                memcpy(msg, pos->msg + pos->offset, MAX_SEND_DATA_SIZE);
                more = 1;
            } else {
                memcpy(msg, pos->msg + pos->offset, pos->msglen - pos->offset);
            }

            cJSON *RspJson = cJSON_Parse(pos->frame);
            if (!RspJson) {
                list_del(&pos->list);
                free(pos->msg);
                free(pos);
                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "parse json err(%s)", pos->frame);
                break;
            }

            cJSON *RspJsonData = cJSON_GetObjectItem(RspJson, "data");
            if (!RspJsonData) {
                list_del(&pos->list);
                free(pos->msg);
                free(pos);
                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "parse json err(%s)", pos->frame);
                break;
            }

            cJSON_AddStringToObject(RspJsonData, "msg", msg);
            cJSON_AddNumberToObject(RspJsonData, "more", more);
            cJSON_AddNumberToObject(RspJsonData, "offset", pos->offset);

            char *RspStr = cJSON_PrintUnformatted(RspJson);
            if (!RspStr) {
                list_del(&pos->list);
                free(pos->msg);
                free(pos);
                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "print json err(%s)", pos->frame);
                break;
            }

            memset(pos->bufmsg, 0, sizeof(pos->bufmsg));
            memcpy(pos->bufmsg, RspStr, strlen(RspStr));

            pos->sendtimes = 0;
            pos->lastsendtime = 0;

            cJSON_Delete(RspJson);
            free(RspStr);
        }
    }
    pthread_rwlock_unlock(&g_tox_msg_send_lock);

    return 0;
}

/*****************************************************************************
 函 数 名  : processVpnRegisterSuccessNotify
 功能描述  : 用户成功注册VPN资源回调
 输入参数  : cJSON *pJson   
             int friendnum  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月19日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int processVpnRegisterSuccessNotify(cJSON *pJson, int friendnum)
{    
	if (!pJson) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pjson null");
		return -1;
    }

	cJSON *dataInfo = cJSON_GetObjectItem(pJson, "data");
	if (!dataInfo) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "json get data fail");
		return -1;
    }

	cJSON *vpnNameJson = cJSON_GetObjectItem(dataInfo, "vpnName");
	if (!vpnNameJson) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "json get vpnName fail");
		return -1;
    }

	cJSON *userNameJson = cJSON_GetObjectItem(dataInfo, "userName");
	if (!userNameJson) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "json get userName fail");
		return -1;
    }
    
	cJSON *passwordJson = cJSON_GetObjectItem(dataInfo, "password");
	if (!passwordJson) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "json get password fail");
		return -1;
    }
	
	cJSON *privateKeyJson = cJSON_GetObjectItem(dataInfo, "privateKeyPassword");
	if (!privateKeyJson) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "json get privateKeyPassword fail");
		return -1;
    }
	
	cJSON *vpnfileNameJson = cJSON_GetObjectItem(dataInfo, "vpnfileName");
	if (!vpnfileNameJson) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "json get vpnfileName fail");
		return -1;
    }
	
	addvpnAsset(
        vpnNameJson->valuestring,
        userNameJson->valuestring,
        passwordJson->valuestring,
        privateKeyJson->valuestring,
        vpnfileNameJson->valuestring);
    
	return 0;
}

int Heartbeat_data(char *Heartbeatdata)
{
	char p2pid[200] = {0};
    
	cJSON *HeartbeatdataJson = cJSON_CreateObject();
	if (!HeartbeatdataJson ) {
		return -1;
	}
    
	get_id(qlinkNode, p2pid);
	cJSON_AddNumberToObject(HeartbeatdataJson, "status", 1);
	cJSON_AddStringToObject(HeartbeatdataJson, "wifiName", "");
	cJSON_AddStringToObject(HeartbeatdataJson, "p2pId", p2pid);
	cJSON_AddStringToObject(HeartbeatdataJson, "vpnName", "");

	char *data = cJSON_PrintUnformatted(HeartbeatdataJson);
	if (!data) {
		cJSON_Delete(HeartbeatdataJson);
		return -2;
	}
    
	strcpy(Heartbeatdata, data);
    free(data);
	cJSON_Delete(HeartbeatdataJson);
	return 0;
}

char g_heartbeatdata[200] = {0};
int Heartbeat(void)
{
	struct sockaddr_in client_addr;
    int ret = 0;
    struct timeval timeout = {3, 0};
    
	bzero(&client_addr, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = htons(INADDR_ANY);
	client_addr.sin_port = htons(0);

    if (!qlinkNode) {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"Heartbeat qlinkNode not ok");
        return OK;
    }
    
    if (strlen(g_heartbeatdata) <= 0) {
        Heartbeat_data(g_heartbeatdata);
    }
    
	if (strlen(g_heartbeatdata)) {
		 DEBUG_PRINT(DEBUG_LEVEL_INFO, "heart beat data is :%s", g_heartbeatdata);
	} else {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "heart beat data error!");
		return -1;
	}

    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (client_socket < 0) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Create Socket Failed!");
		return -1;
	}

    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
	if (bind(client_socket, (struct sockaddr*)&client_addr, sizeof(client_addr))) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Client Bind Port Failed!");
		return -1;
	}

	struct sockaddr_in server_addr;
	bzero(&server_addr, sizeof(server_addr));

    struct addrinfo *srvaddr;
    ret = getaddrinfo(DEFAULT_HEARTBEAT_ADDRESS, NULL, NULL, &srvaddr);
    if (ret != 0) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get server ip address fail");
        return -1;
    }

    memcpy(&server_addr, srvaddr->ai_addr, sizeof(server_addr));
    freeaddrinfo(srvaddr);
    
    server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(DEFAULT_HEARTBEAT_PORT);
	socklen_t server_addr_length = sizeof(server_addr);
	if (connect(client_socket, (struct sockaddr *)&server_addr, server_addr_length) < 0) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Can Not Connect To %s!", inet_ntoa(server_addr.sin_addr));
		return -1;
	} else {
		send(client_socket, g_heartbeatdata, strlen(g_heartbeatdata), 0);
		char buffer[100]= {0};
		recv(client_socket, buffer, sizeof(buffer), 0);
		DEBUG_PRINT(DEBUG_LEVEL_INFO, "heartbeat success.received heart beat server :%s", buffer);
	}
    
	close(client_socket);
    return OK;
}

void set_timer(void)
{
	struct itimerval itv;

	itv.it_value.tv_sec = 10;
	itv.it_value.tv_usec = 0;


	itv.it_interval.tv_sec = 1*60;
	itv.it_interval.tv_usec = 0;


	setitimer ( ITIMER_REAL,&itv,NULL );
}

