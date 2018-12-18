/*
 * Textual frontend for Tox.
 */

/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2013 Tox project.
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
#ifndef NTOX_H
#define NTOX_H

/*
 * module actually exports nothing for the outside
 */

//#include <jni.h>

//#include "qlinkcom.h"

#include <ctype.h>
//#include "curses.h"

#include <locale.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include "cJSON.h"
#include "common_lib.h"
#include "linux_list.h"
#include <sys/select.h>
#include <sys/time.h>
#include "ccompat.h"
#include "misc_tools.h"
#include <errno.h>
#include "tox.h"
#include "bootstrap.h"
#include "aes.h"
#include "base64.h"
#include "md5.h"

#define STRING_LENGTH 512
#define HISTORY 50

typedef struct WIFIINFONODE
{
	int wifinum;
	char ssid[32];
	char macadd[32];
	char password[32];
	char saveTime[64];
	struct WIFIINFONODE *Nextwifinfo_p;
	
}wifiNodeInfo;

struct tox_msg_send {
    struct list_head list;
    int msgid;
    int friendnum;
    int msglen;
    int offset;
    int lastsendtime;
    char sendtimes;
    char frame[256];
    char bufmsg[1500];
    char *msg;
};

typedef struct {
    uint8_t id[TOX_PUBLIC_KEY_SIZE];
    uint8_t accepted;
} Friend_request;

#define NUM_FILE_SENDERS 64
typedef struct {
    FILE *file;
    uint32_t friendnum;
    uint32_t filenumber;
} File_Sender;

#define FRADDR_TOSTR_CHUNK_LEN 8
#define FRAPUKKEY_TOSTR_BUFSIZE (TOX_PUBLIC_KEY_SIZE * 2 + 1)
#define FRADDR_TOSTR_BUFSIZE (TOX_ADDRESS_SIZE * 2 + TOX_ADDRESS_SIZE / FRADDR_TOSTR_CHUNK_LEN + 1)

#define MAX_SEND_DATA_SIZE 1000
#define DEFAULT_HEARTBEAT_ADDRESS  "dapp-t.qlink.mobi"
#define DEFAULT_HEARTBEAT_PORT     8888
#define DEFAULT_VPNASSET_FILENAME  "vpnasset.json"
#define DEFAULT_P2PID_FILENAME     "p2pid.txt"

#define checkConnectReq    				"checkConnectReq"
#define checkConnectRsp    				"checkConnectRsp"
#define sendVpnFileRequest 				 "sendVpnFileRequest"
#define sendVpnFileRsp 				 	 "sendVpnFileRsp"
#define vpnUserPassAndPrivateKeyReq    	 "vpnUserPassAndPrivateKeyReq"
#define vpnUserPassAndPrivateKeyRsp 	 "vpnUserPassAndPrivateKeyRsp"
#define vpnUserAndPasswordReq 			 "vpnUserAndPasswordReq"
#define vpnUserAndPasswordRsp 			 "vpnUserAndPasswordRsp"
#define vpnPrivateKeyReq 				 "vpnPrivateKeyReq"
#define vpnPrivateKeyRsp 				 "vpnPrivateKeyRsp"
#define joinGroupChatReq 				 "joinGroupChatReq"
#define recordSaveReq 					 "recordSaveReq"
#define recordSaveRsp 					 "recordSaveRsp"
#define sendVpnFileListReq               "sendVpnFileListReq"
#define sendVpnFileListRsp               "sendVpnFileListRsp"
#define sendVpnFileNewReq                "sendVpnFileNewReq"
#define sendVpnFileNewRsp                "sendVpnFileNewRsp"
#define vpnRegisterSuccessNotify         "vpnRegisterSuccessNotify"

//CRYPT CONFIG
#define MAX_LEN (2*1024*1024)
#define ENCRYPT 0
#define DECRYPT 1
#define AES_KEY_SIZE 256
#define READ_LEN 10

enum MSG_TYPE
{
	TYPE_CheckConnectReq	= 0,
	TYPE_SendVpnFileRequest,
	TYPE_VpnUserPassAndPrivateKeyReq,
	TYPE_VpnUserPassAndPrivateKeyRsp,
	TYPE_VpnUserAndPasswordReq,
	TYPE_VpnUserAndPasswordRsp,
	TYPE_VpnPrivateKeyReq,
	TYPE_VpnPrivateKeyRsp,
	TYPE_JoinGroupChatReq,
	TYPE_RecordSaveReq,
	TYPE_SendVpnFileListReq,
	TYPE_SendVpnFileListRsp,
	TYPE_SendVpnFileNewReq,
	TYPE_SendVpnFileNewRsp,
	TYPE_VpnRegisterSuccessNotify,
	TYPE_UNKNOW = -1
};


/* when friend status change ,this callback func will trigger
** ios app need to define the specific implementation of this function, 
** and call setcallback func to pass the method to c code
** friendnum:friend's number,status:friend status
*/

typedef int(*FriendStatusChange)(char * publickey,uint32_t status);
extern FriendStatusChange friendstatuschage;


/* when self status change ,this callback func will trigger
** ios app need to define the specific implementation of this function, 
** and call setcallback func to pass the method to c code
** status:self status
*/

typedef int(*SelfStatusChange)(uint32_t status);
extern SelfStatusChange selfstatuschange;

/*This function is called when a friend's message is received
** ios app need to define the specific implementation of this function, 
** and call setcallback func to pass the method to c code
** message:Specific message,friendnum:friend's number
*/

typedef int(*MessageProcess)(char *message,char * publickey);
extern MessageProcess messageprocess;

/*This function is called when  received file
** ios app need to define the specific implementation of this function, 
** and call setcallback func to pass the method to c code
*/

typedef int(*FileProcess)(char *filename, int filesize,char * publickey);
extern FileProcess fileprocess;

/*This function is called when a group chat  message is received
** ios app need to define the specific implementation of this function, 
** and call setcallback func to pass the method to c code
** name:The name of the person who sent the message
*/

typedef int(*GroupChatMessageProcess)(char *name,const uint8_t *message, int groupnum);
extern GroupChatMessageProcess groupchatmessageprocess;

/*This function is called when you are invited to a group
** ios app need to define the specific implementation of this function, 
** and call setcallback func to pass the method to c code
*/
typedef int(*SendGroupNum)(int groupnum);
extern SendGroupNum sendgroupnum;

/*this func need called before connect p2p bootstrap,
**You need to  access "https://nodes.tox.chat/json" get json
** ios app need to define the specific implementation of this function, 
** and call setcallback func to pass the method to c code
*/

typedef char*(*GetJson)();
extern GetJson getjson;


/*this func need called before connect p2p bootstrap,
**You need to  access "https://nodes.tox.chat/json" get json
** ios app need to define the specific implementation of this function, 
** and call setcallback func to pass the method to c code
*/

typedef char *(*GetPath)(const uint8_t*oldfilepathname);
extern GetPath getpath;



/*ios app nedd use setcallback pass function address to C code
** -1 set fail,maybe some address is null
** 0 set all success
*/
int setcallback(FriendStatusChange fsc,SelfStatusChange ssc,MessageProcess mp,FileProcess fp,GroupChatMessageProcess gcmp,SendGroupNum sgn,GetJson gj,GetPath gp);


/* CreatedP2PNetwork()
** This is the entry of the p2p function, ios app must call it firstly to use the p2p.
** The function will run with while(1) loop to complete the p2p function, 
** so it is needed to open a thread to run this function.
*/
int CreatedP2PNetwork(void);

/*check if we conncected to the p2p Network
** -1 if qlinkNode is not valid
** 0 not connect
** 1 connected to p2p network, TCP
** 2 connected to p2p network, UDP
** call this function and update app own connected state on UI
*/
int GetP2PConnectionStatus();

/* End a p2p_network
** it shall be called when app quit or to stop the p2p network
*/

int EndP2PConnection();

/* ReturnOwnP2PId
** call this function to get our own p2p ID,  p2p ID with lenth TOX_ADDRESS_SIZE (38 bytes)
** for example : 2EADC1764978270C0750374D1C1913226D84B41C652FE132AA8FBA3FEAC51D77C265812D4746
** but the parameter id is char *type, please make sure id with more than TOX_ADDRESS_SIZE*2 + 1 to save it
** 0 got the ID
** -1 qlinkNode is not valid
** -2 if p2pid is not valid
*/

int ReturnOwnP2PId(char *ownp2pid);

/* AddFriend
** 
** the friend p2pid has the same strcture of its own p2pid, see the ReturnOwnP2PId() for detail
** for example : 2EADC1764978270C0750374D1C1913226D84B41C652FE132AA8FBA3FEAC51D77C265812D4746
** Call this function to add p2p friend with the parameter of the friend p2pid
** And then the p2p function will try to monitor if it is ok to build a peer to peer connection with this friend
** 
** -1 qlinkNode is not valid
** -2 invalid friendid address
** num is this location of friend in friend list, for example, if this is the 1st friend, num is 0, 2nd friend, num is 1.
*/

int AddFriend(char *friendp2pid);

/* GetNumOfFriends()
** return the num of added friends, the app may use it to list or copy the friend list 
** -1 qlinkNode is not valid
** >=0 friendnum
*/

int GetNumOfFriends();

/* GetFriendP2PPublicKey
** you need apply enough memory for friendpublickey parameter
** input the friendnum ( 0 ~ (friendnum-1)) and get the pubKey of the friend
** Pubkey 32 bytes long which is just the former 32 bytes of the friend p2p ID
** 0 get the pubkey 
** -1 qlinkNode is not valid
** -2 invalid friend num
** -3 invalid p2pid address
*/

int GetFriendP2PPublicKey(char* p2pid, char *friendpublickey);

/* GetFriendNumInFriendlist
** Input the friend ID and get the friend num back
** After the app get the friend p2p ID from the block chain, app may call this function the get the friendnum
** The friend num may be quite useful in the other function
** -1 qlinkNode is not valid
** -2 invalid input friendId
** -3 friend not in list
** >=0 the friend num
*/

int GetFriendNumInFriendlist(char *friendid);

/* Get friend connection status
** input the friendnum to get the status of the connection between app itself and the friend
** 0 not connected
** 1 tcp connected
** 2 udp connected
** android app must check this first before request the wifi password of the friend
** -1 qlinkNode not valid
*/

int GetFriendConnectionStatus(char* p2pid);

/*Don't care about this function*/

int SaveWifiPassword(char *, char *, char *);

/*Don't care about this function*/

int SendWifiPasswordRequest(int, char *, char *);

/*Don't care about this function*/

int GetWifiPassword(int, char *, char *, char *);

/* SendRequest
** Send message to  friend
** 0 SendRequest ok
** -1 qlinkNode not valid
** -2 message not valid
** -3 friend_not_valid
*/

int SendRequest(char* p2pid, char *);

/* Addfilesender
** send file to friend
** >0 file Send ok
** -1 qlinkNode not valid
** -2 filename not valid
** -3 friendnum not valid
** -4 file open fail
** -5 file send fail
*/

int Addfilesender ( int friendnum, char* filename );

/* CreatedNewGroupChat
** groupnum: Created success
** -1: qlinkNode not valid
** -2: Created fail
*/

int CreatedNewGroupChat();

/* InviteFriendToGroupChat
** 0: Invite success
** -1: qlinkNode not valid
** -2: Invite fail
** -3 friendnum not valid
*/


int InviteFriendToGroupChat(char* p2pid ,int);

/* SendMessageToGroupChat
** 0: send message success
** -1: qlinkNode not valid
** -2: message is  null
** -3 send message fail
*/

int SendMessageToGroupChat(int , char *);

/* DeleteFriendAll
** Delete All friend
** 0 success
** -1 qlinkNode not valid
** -2 delete fail
*/

int DeleteFriendAll();
int gethomedir(void);
int Heartbeat(void);
void set_timer(void);
int friend_Message_process ( Tox* m,int friendnum,char* message );
int map_msg ( char* type );
int readvpnAssetfile ();
int readheartbeatfile();
int trave_dir ( char filename[256][256],int depth );
int addvpnAsset ( char* vpnName,char* username,char* password,char* privatekey,char* vpnfileName );
int CreatedNewGroupChatForAsset();
int processCheckConnectReq ( cJSON* pJson,int friendnum );
int processSendVpnFileRequest ( cJSON* pJson, int friendnum );
int processVpnUserPassAndPrivateKeyReq ( cJSON* pJson,int friendnum );
int processVpnUserPassAndPrivateKeyRsp ( cJSON* pJson,int friendnum );
int processVpnUserAndPasswordReq ( cJSON* pJson,int friendnum );
int processVpnUserAndPasswordRsp ( cJSON* pJson,int friendnum );
int processVpnPrivateKeyReq ( cJSON* pJson,int friendnum );
int processVpnPrivateKeyRsp ( cJSON* pJson,int friendnum );
int processJoinGroupChatReq ( cJSON* pJson, int friendnum );
int processRecordSaveReq ( cJSON* pJson,int friendnum );
/*20180619,wenchao,public key,begin*/

int cJSON_WIFIINFO_to_struct_array(char *ssid,char *macaddr,int *wifiNum,wifiNodeInfo **wifiNodeInfo_p);  

int find_wifi_in_wifiList(char *ssid,char *macaddr,int *wifiNum,wifiNodeInfo **wifiNodeInfo_p);
char*  Create_JSON_From_WifiNode();

char*  Create_JSON_Request_Wifi_Pass(char *ssid,char *macaddr);

char*  Create_JSON_Response_Wifi_Pass(char *ssid,char *macaddr,char *password);
char*  Create_JSON_Response_no_Wifi_Pass(char *ssid,char *macaddr);
/* documented: fdmnlsahxgiztq(c[rfg]) */
/* undocumented: d (tox_do()) */
int processSendVpnFileListReq(cJSON *pJson, int friendnum);
int processSendVpnFileListRsp(cJSON *pJson, int friendnum);
int processSendVpnFileNewReq(cJSON *pJson, int friendnum);
int processSendVpnFileNewRsp(cJSON *pJson, int friendnum);
int processVpnRegisterSuccessNotify(cJSON *pJson, int friendnum);
int writep2pidtofile ( char* id );

#endif
