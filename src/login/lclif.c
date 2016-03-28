/**
 * This file is part of Hercules.
 * http://herc.ws - http://github.com/HerculesWS/Hercules
 *
 * Copyright (C) 2016  Hercules Dev Team
 *
 * Hercules is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#define HERCULES_CORE

#include "lclif.p.h"

#include "login/ipban.h"
#include "login/login.h"
#include "login/loginlog.h"
#include "common/HPM.h"
#include "common/cbasetypes.h"
#include "common/db.h"
#include "common/md5calc.h"
#include "common/memmgr.h"
#include "common/mmo.h"
#include "common/nullpo.h"
#include "common/random.h"
#include "common/showmsg.h"
#include "common/socket.h"
#include "common/strlib.h"
#include "common/utils.h"

struct lclif_interface lclif_s;
struct lclif_interface_private lclif_p;
struct lclif_interface *lclif;

struct login_packet_db packet_db[MAX_PACKET_DB + 1];

void lclif_connection_error(int fd, uint8 error)
{
	struct PACKET_SC_NOTIFY_BAN *packet = NULL;
	WFIFOHEAD(fd, sizeof(*packet));
	packet = WP2PTR(fd);
	packet->PacketID = PACKET_ID_SC_NOTIFY_BAN;
	packet->ErrorCode = error;
	WFIFOSET(fd, sizeof(*packet));
}

DEFPACKET(CA_CONNECT_INFO_CHANGED)
{
	// New alive packet: structure: 0x200 <account.userid>.24B. used to verify if client is always alive.
	return PACKET_VALID;
}

DEFPACKET(CA_EXE_HASHCHECK)
{
	// S 0204 <md5 hash>.16B (kRO 2004-05-31aSakexe langtype 0 and 6)
	const struct PACKET_CA_EXE_HASHCHECK *packet = RP2PTR(fd);
	sd->has_client_hash = 1;
	memcpy(sd->client_hash, packet->HashValue, 16);
	return PACKET_VALID;
}

DEFPACKET(CA_LOGIN)
{
	// S 0064 <version>.L <username>.24B <password>.24B <clienttype>.B
	const struct PACKET_CA_LOGIN *packet = RP2PTR(fd);

	sd->version = packet->Version;
	sd->clienttype = packet->clienttype;
	safestrncpy(sd->userid, packet->ID, NAME_LENGTH);
	safestrncpy(sd->passwd, packet->Passwd, PASSWD_LEN);

	if (login->config->use_md5_passwds)
		MD5_String(sd->passwd, sd->passwd);
	sd->passwdenc = PWENC_NONE;

	login->client_login(fd, sd);
	return PACKET_VALID;
}

DEFPACKET(CA_LOGIN2)
{
	// S 01dd <version>.L <username>.24B <password hash>.16B <clienttype>.B
	const struct PACKET_CA_LOGIN2 *packet = RP2PTR(fd);

	sd->version = packet->Version;
	sd->clienttype = packet->clienttype;
	safestrncpy(sd->userid, packet->ID, NAME_LENGTH);
	bin2hex(sd->passwd, packet->PasswdMD5, 16);
	sd->passwdenc = PASSWORDENC;

	login->client_login(fd, sd);
	return PACKET_VALID;
}

DEFPACKET(CA_LOGIN3)
{
	// S 01fa <version>.L <username>.24B <password hash>.16B <clienttype>.B <?>.B(index of the connection in the clientinfo file (+10 if the command-line contains "pc"))
	const struct PACKET_CA_LOGIN3 *packet = RP2PTR(fd);

	sd->version = packet->Version;
	sd->clienttype = packet->clienttype;
	/* unused */
	/* sd->clientinfo = packet->ClientInfo; */
	safestrncpy(sd->userid, packet->ID, NAME_LENGTH);
	bin2hex(sd->passwd, packet->PasswdMD5, 16);
	sd->passwdenc = PASSWORDENC;

	login->client_login(fd, sd);
	return PACKET_VALID;
}

DEFPACKET(CA_LOGIN4)
{
	// S 027c <version>.L <username>.24B <password hash>.16B <clienttype>.B <?>.13B(junk)
	const struct PACKET_CA_LOGIN4 *packet = RP2PTR(fd);

	sd->version = packet->Version;
	sd->clienttype = packet->clienttype;
	/* unused */
	/* safestrncpy(sd->macdata, packet->macData, sizeof(sd->macdata)); */
	safestrncpy(sd->userid, packet->ID, NAME_LENGTH);
	bin2hex(sd->passwd, packet->PasswdMD5, 16);
	sd->passwdenc = PASSWORDENC;

	login->client_login(fd, sd);
	return PACKET_VALID;
}

DEFPACKET(CA_LOGIN_PCBANG)
{
	// S 0277 <version>.L <username>.24B <password>.24B <clienttype>.B <ip address>.16B <adapter address>.13B
	const struct PACKET_CA_LOGIN_PCBANG *packet = RP2PTR(fd);

	sd->version = packet->Version;
	sd->clienttype = packet->clienttype;
	/* unused */
	/* safestrncpy(sd->ip, packet->IP, sizeof(sd->ip)); */
	/* safestrncpy(sd->macdata, packet->MacAdress, sizeof(sd->macdata)); */
	safestrncpy(sd->userid, packet->ID, NAME_LENGTH);
	safestrncpy(sd->passwd, packet->Passwd, PASSWD_LEN);

	if (login->config->use_md5_passwds)
		MD5_String(sd->passwd, sd->passwd);
	sd->passwdenc = PWENC_NONE;

	login->client_login(fd, sd);
	return PACKET_VALID;
}

DEFPACKET(CA_LOGIN_HAN)
{
	// S 02b0 <version>.L <username>.24B <password>.24B <clienttype>.B <ip address>.16B <adapter address>.13B <g_isGravityID>.B
	const struct PACKET_CA_LOGIN_HAN *packet = RP2PTR(fd);

	sd->version = packet->Version;
	sd->clienttype = packet->clienttype;
	/* unused */
	/* safestrncpy(sd->ip, packet->m_szIP, sizeof(sd->ip)); */
	/* safestrncpy(sd->macdata, packet->m_szMacAddr, sizeof(sd->macdata)); */
	/* sd->ishan = packet->isHanGameUser; */
	safestrncpy(sd->userid, packet->ID, NAME_LENGTH);
	safestrncpy(sd->passwd, packet->Passwd, PASSWD_LEN);

	if (login->config->use_md5_passwds)
		MD5_String(sd->passwd, sd->passwd);
	sd->passwdenc = PWENC_NONE;

	login->client_login(fd, sd);
	return PACKET_VALID;
}

DEFPACKET(CA_SSO_LOGIN_REQ)
{
	// S 0825 <packetsize>.W <version>.L <clienttype>.B <userid>.24B <password>.27B <mac>.17B <ip>.15B <token>.(packetsize - 0x5C)B
	const struct PACKET_CA_SSO_LOGIN_REQ *packet = RP2PTR(fd);
	int tokenlen = (int)RFIFOREST(fd) - (int)sizeof(*packet);

	if (tokenlen > PASSWD_LEN || tokenlen < 1) {
		ShowError("PACKET_CA_SSO_LOGIN_REQ: Token length is not between allowed password length, kicking player ('%s')", packet->ID);
		sockt->eof(fd);
		return PACKET_VALID;
	}

	sd->clienttype = packet->clienttype;
	sd->version = packet->Version;
	safestrncpy(sd->userid, packet->ID, NAME_LENGTH);
	safestrncpy(sd->passwd, packet->t1, min(tokenlen + 1, PASSWD_LEN)); // Variable-length field, don't copy more than necessary

	if (login->config->use_md5_passwds)
		MD5_String(sd->passwd, sd->passwd);
	sd->passwdenc = PWENC_NONE;

	login->client_login(fd, sd);
	return PACKET_VALID;
}

DEFPACKET(CA_REQ_HASH)
{
	memset(sd->md5key, '\0', sizeof(sd->md5key));
	sd->md5keylen = (uint16)(12 + rnd() % 4);
	MD5_Salt(sd->md5keylen, sd->md5key);

	lclif->coding_key(fd, sd);
	return PACKET_VALID;
}

DEFPACKET(CA_CHARSERVERCONNECT)
{
	char ip[16];
	uint32 ipl = sockt->session[fd]->client_addr;
	sockt->ip2str(ipl, ip);

	login->parse_request_connection(fd, sd, ip, ipl);

	return PACKET_STOPPARSE;
}

bool lclif_send_server_list(struct login_session_data *sd)
{
	int server_num = 0, i, n, length;
	uint32 ip;
	struct PACKET_AC_ACCEPT_LOGIN *packet = NULL;

	for (i = 0; i < ARRAYLENGTH(server); ++i) {
		if (sockt->session_is_active(server[i].fd))
			server_num++;
	}
	if (server_num == 0)
		return false;

	length = sizeof(*packet) + sizeof(packet->ServerList[0]) * server_num;
	ip = sockt->session[sd->fd]->client_addr;

	// Allocate the packet
	WFIFOHEAD(sd->fd, length);
	packet = WP2PTR(sd->fd);

	packet->PacketType = PACKET_ID_AC_ACCEPT_LOGIN;
	packet->PacketLength = length;
	packet->AuthCode = sd->login_id1;
	packet->AID = sd->account_id;
	packet->userLevel = sd->login_id2;
	packet->lastLoginIP = 0; // Not used anymore
	memset(packet->lastLoginTime, '\0', sizeof(packet->lastLoginTime)); // Not used anymore
	packet->Sex = sex_str2num(sd->sex);
	for (i = 0, n = 0;  i < ARRAYLENGTH(server); ++i) {
		uint32 subnet_char_ip;

		if (!sockt->session_is_valid(server[i].fd))
			continue;

		subnet_char_ip = login->lan_subnet_check(ip);
		packet->ServerList[n].ip = htonl((subnet_char_ip) ? subnet_char_ip : server[i].ip);
		packet->ServerList[n].port = sockt->ntows(htons(server[i].port)); // [!] LE byte order here [!]
		safestrncpy(packet->ServerList[n].name, server[i].name, 20);
		packet->ServerList[n].usercount = server[i].users;

		if (server[i].type == CST_PAYING && sd->expiration_time > time(NULL))
			packet->ServerList[n].property = CST_NORMAL;
		else
			packet->ServerList[n].property = server[i].type;

		packet->ServerList[n].state = server[i].new_;
		++n;
	}
	WFIFOSET(sd->fd, length);

	return true;
}

void lclif_send_auth_failed(int fd, time_t ban, uint32 error)
{
#if PACKETVER >= 20120000 /* not sure when this started */
	struct PACKET_AC_REFUSE_LOGIN_R2 *packet = NULL;
	int packet_id = PACKET_ID_AC_REFUSE_LOGIN_R2;
#else
	struct PACKET_AC_REFUSE_LOGIN *packet = NULL;
	int packet_id = PACKET_ID_AC_REFUSE_LOGIN;
#endif
	WFIFOHEAD(fd, sizeof(*packet));
	packet = WP2PTR(fd);
	packet->PacketID = packet_id;
	packet->ErrorCode = error;
	if (error == 6)
		timestamp2string(packet->blockDate, sizeof(packet->blockDate), ban, login->config->date_format);
	else
		memset(packet->blockDate, '\0', sizeof(packet->blockDate));
	WFIFOSET(fd, sizeof(*packet));
}

void lclif_send_login_error(int fd, uint8 error)
{
	struct PACKET_AC_REFUSE_LOGIN *packet = NULL;
	WFIFOHEAD(fd, sizeof(*packet));
	packet = WP2PTR(fd);
	packet->PacketID = PACKET_ID_AC_REFUSE_LOGIN;
	packet->ErrorCode = error;
	memset(packet->blockDate, '\0', sizeof(packet->blockDate));
	WFIFOSET(fd, sizeof(*packet));
}

void lclif_send_coding_key(int fd, struct login_session_data *sd)
{
	struct PACKET_AC_ACK_HASH *packet = NULL;
	int16 size = sizeof(*packet) + sd->md5keylen;

	WFIFOHEAD(fd, size);
	packet = WP2PTR(fd);
	packet->PacketID = PACKET_ID_AC_ACK_HASH;
	packet->PacketLength = size;
	memcpy(packet->secret, sd->md5key, sd->md5keylen);
	WFIFOSET(fd, size);
}

int lclif_parse(int fd)
{
	struct login_session_data *sd = NULL;
	int i;
	char ip[16];
	uint32 ipl = sockt->session[fd]->client_addr;
	sockt->ip2str(ipl, ip);

	if (sockt->session[fd]->flag.eof) {
		ShowInfo("Closed connection from '"CL_WHITE"%s"CL_RESET"'.\n", ip);
		sockt->close(fd);
		return 0;
	}

	if ((sd = sockt->session[fd]->session_data) == NULL) {
		// Perform ip-ban check
		if (login->config->ipban && !sockt->trusted_ip_check(ipl) && ipban_check(ipl)) {
			ShowStatus("Connection refused: IP isn't authorized (deny/allow, ip: %s).\n", ip);
			login_log(ipl, "unknown", -3, "ip banned");
			lclif->login_error(fd, 3); // 3 = Rejected from Server
			sockt->eof(fd);
			return 0;
		}

		// create a session for this new connection
		CREATE(sockt->session[fd]->session_data, struct login_session_data, 1);
		sd = sockt->session[fd]->session_data;
		sd->fd = fd;
	}

	for (i = 0; i < MAX_PROCESSED_PACKETS; ++i) {
		enum parsefunc_rcode result;
		int16 packet_id = RFIFOW(fd, 0);
		int packet_len = (int)RFIFOREST(fd);

		if (packet_len < 2)
			return 0;

		result = lclif->parse_sub(fd, sd);

		switch (result) {
		case PACKET_SKIP:
			continue;
		case PACKET_INCOMPLETE:
		case PACKET_STOPPARSE:
			return 0;
		case PACKET_UNKNOWN:
			ShowWarning("lclif_parse: Received unsupported packet (packet 0x%04x, %d bytes received), disconnecting session #%d.\n", (unsigned int)packet_id, packet_len, fd);
#ifdef DUMP_INVALID_PACKET
			ShowDump(RFIFOP(fd, 0), RFIFOREST(fd));
#endif
			sockt->eof(fd);
			return 0;
		case PACKET_INVALIDLENGTH:
			ShowWarning("lclif_parse: Received packet 0x%04x specifies invalid packet_len (%d), disconnecting session #%d.\n", (unsigned int)packet_id, packet_len, fd);
#ifdef DUMP_INVALID_PACKET
			ShowDump(RFIFOP(fd, 0), RFIFOREST(fd));
#endif
			sockt->eof(fd);
			return 0;
		}
	}
	return 0;
}

enum parsefunc_rcode lclif_parse_sub(int fd, struct login_session_data *sd)
{
	int packet_len = (int)RFIFOREST(fd);
	int16 packet_id = RFIFOW(fd, 0);
	struct login_packet_db *lpd;

	if (VECTOR_LENGTH(HPM->packets[hpParse_Login]) > 0) {
		int result = HPM->parse_packets(fd, packet_id, hpParse_Login);
		if (result == 1)
			return PACKET_VALID;
		if (result == 2)
			return PACKET_INCOMPLETE; // Packet not completed yet
	}

	lpd = lclif->packet(packet_id);

	if (lpd == NULL)
		return PACKET_UNKNOWN;

	if (lpd->len == 0)
		return PACKET_UNKNOWN;

	if (lpd->len > 0 && lpd->pFunc == NULL)
		return PACKET_UNKNOWN; //This Packet is defined for length purpose ? should never be sent from client ?

	if (lpd->len == -1) {
		uint16 packet_var_len = 0; //Max Variable Packet length is signed int16 size

		if (packet_len < 4)
			return PACKET_INCOMPLETE; //Packet incomplete

		packet_var_len = RFIFOW(fd, 2);

		if (packet_var_len < 4 || packet_var_len > SINT16_MAX)
			return PACKET_INVALIDLENGTH; //Something is wrong, close connection.

		if (RFIFOREST(fd) < packet_var_len)
			return PACKET_INCOMPLETE; //Packet incomplete again.

		return lclif->parse_packet(lpd, fd, sd);
	} else if (lpd->len <= packet_len) {
		return lclif->parse_packet(lpd, fd, sd);
	}

	return PACKET_VALID;
}

struct login_packet_db *lclif_packet(int16 packet_id)
{
	if (packet_id == PACKET_ID_CA_CHARSERVERCONNECT)
		return &packet_db[0];

	if (packet_id > MAX_PACKET_DB || packet_id < MIN_PACKET_DB)
		return NULL;

	return &packet_db[packet_id];
}

int lclif_parse_packet(struct login_packet_db *lpd, int fd, struct login_session_data *sd)
{
	int result;
	result = lpd->pFunc(fd, sd);
	RFIFOSKIP(fd, (lpd->len == -1) ? RFIFOW(fd, 2) : lpd->len);
	return result;
}

void packetdb_loaddb(void)
{
	int i;
	struct packet {
		int16 packet_id;
		int16 packet_len;
		int (*pFunc)(int, struct login_session_data *);
	} packet[] = {
		packet_def(CA_CONNECT_INFO_CHANGED),
		packet_def(CA_EXE_HASHCHECK),
		packet_def(CA_LOGIN),
		packet_def(CA_LOGIN2),
		packet_def(CA_LOGIN3),
		packet_def(CA_LOGIN4),
		packet_def(CA_LOGIN_PCBANG),
		packet_def(CA_LOGIN_HAN),
		packet_def2(CA_SSO_LOGIN_REQ, -1),
		packet_def(CA_REQ_HASH),
	};
	int length = ARRAYLENGTH(packet);

	memset(packet_db, '\0', sizeof(packet_db));

	for (i = 0; i < length; ++i) {
		int16 packet_id = packet[i].packet_id;
		Assert_retb(packet_id >= MIN_PACKET_DB && packet_id < MAX_PACKET_DB);
		packet_db[packet_id].len = packet[i].packet_len;
		packet_db[packet_id].pFunc = packet[i].pFunc;
	}

	//Explict case, we will save character login packet in position 0 which is unused and not valid by normal
	packet_db[0].len = sizeof(struct PACKET_CA_CHARSERVERCONNECT);
	packet_db[0].pFunc = lclif_parse_CA_CHARSERVERCONNECT;
}

void lclif_init(void)
{
	lclif->p->packetdb_loaddb();
}

void lclif_final(void)
{
}

void lclif_defaults(void)
{
	lclif = &lclif_s;
	lclif->p = &lclif_p;

	lclif->init = lclif_init;
	lclif->final = lclif_final;

	lclif->connection_error = lclif_connection_error;
	lclif->server_list = lclif_send_server_list;
	lclif->auth_failed = lclif_send_auth_failed;
	lclif->login_error = lclif_send_login_error;
	lclif->coding_key = lclif_send_coding_key;

	lclif->packet = lclif_packet;
	lclif->parse_packet = lclif_parse_packet;
	lclif->parse = lclif_parse;
	lclif->parse_sub = lclif_parse_sub;

	lclif->p->packetdb_loaddb = packetdb_loaddb;
}
