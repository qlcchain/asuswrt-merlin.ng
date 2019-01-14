#include "rc.h"
#include <shared.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#define WINQ_FILE	"/jffs/winq_server/winq_server"
#define WINQ_SCRIPT	"/jffs/winq_server/ovpn_ip_update"

static int needs_update()
{
	FILE *pf = NULL;
	int verh = 0, verm = 0, verl = 0;
	int rom_ver = 0, jffs_ver = 0;
	char buf[32] = {0};

	pf = popen("/usr/sbin/winq_server --version", "r");
	if (pf) {
		fgets(buf, sizeof(buf), pf);
		sscanf(buf, "%d.%d.%d", &verh, &verm, &verl);
		rom_ver = verh * 10000 + verm * 100 + verl;

		logmessage("WINQSRV", "get rom version %s", buf);
		fclose(pf);
	} else {
		logmessage("WINQSRV", "get rom version err");
		return 1;
	}

	memset(buf, 0, sizeof(buf));
	verh = 0;
	verm = 0;
	verl = 0;
	pf = popen("/jffs/winq_server/winq_server --version", "r");
	if (pf) {
		fgets(buf, sizeof(buf), pf);
		sscanf(buf, "%d.%d.%d", &verh, &verm, &verl);
		jffs_ver = verh * 10000 + verm * 100 + verl;

		logmessage("WINQSRV", "get jffs version %s", buf);
		fclose(pf);
	} else {
		logmessage("WINQSRV", "get jffs version err");
		return 1;
	}

	if (rom_ver > jffs_ver) {
		logmessage("WINQSRV", "winq server needs to update");
		return 1;
	}

	return 0;
}

int start_winq_server(void)
{
	char *winqserver_argv[] = {WINQ_FILE, NULL};

	if (access(WINQ_SCRIPT, F_OK) != 0) {
		system("mkdir -p /jffs/winq_server");
		system("cp /usr/sbin/ovpn_ip_update /jffs/winq_server/");
	}

	if (access(WINQ_FILE, F_OK) != 0) {
		system("mkdir -p /jffs/winq_server");
		system("cp /usr/sbin/winq_server /jffs/winq_server/");
	}

	if (needs_update()) {
		system("cp /usr/sbin/winq_server /jffs/winq_server/");
		system("cp /usr/sbin/ovpn_ip_update /jffs/winq_server/");
	}

	return _eval(winqserver_argv, NULL, 0, NULL);
}

