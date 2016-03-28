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
#ifndef LOGIN_LCLIF_P_H
#define LOGIN_LCLIF_P_H

#include "login/lclif.h"

#include "common/hercules.h"
#include "common/mmo.h"

/* Definitions and macros */
/// Maximum amount of packets processed at once from the same client
#define MAX_PROCESSED_PACKETS (3)

/// Packet definition helper
#define DEFPACKET(name) enum parsefunc_rcode lclif_parse_ ## name (int fd, struct login_session_data *sd)
#define packet_def(name) { PACKET_ID_ ## name, sizeof(struct PACKET_ ## name), lclif_parse_ ## name }
#define packet_def2(name, len) { PACKET_ID_ ## name, (len), lclif_parse_ ## name }

// Packet DB
#define MIN_PACKET_DB 0x0064
#define MAX_PACKET_DB 0x08ff

/* Enums */
/**
 * Packets ID Enum
 */
enum login_packet_id {
	// CA (Client to Login)
	PACKET_ID_CA_LOGIN                = 0x0064,
	PACKET_ID_CA_LOGIN2               = 0x01dd,
	PACKET_ID_CA_LOGIN3               = 0x01fa,
	PACKET_ID_CA_CONNECT_INFO_CHANGED = 0x0200,
	PACKET_ID_CA_EXE_HASHCHECK        = 0x0204,
	PACKET_ID_CA_LOGIN_PCBANG         = 0x0277,
	PACKET_ID_CA_LOGIN4               = 0x027c,
	PACKET_ID_CA_LOGIN_HAN            = 0x02b0,
	PACKET_ID_CA_SSO_LOGIN_REQ        = 0x0825,
	PACKET_ID_CA_REQ_HASH             = 0x01db,
	PACKET_ID_CA_CHARSERVERCONNECT    = 0x2710, // Custom Hercules Packet
	//PACKET_ID_CA_SSO_LOGIN_REQa       = 0x825a, /* unused */

	// AC (Login to Client)
	PACKET_ID_AC_ACCEPT_LOGIN         = 0x0069,
	PACKET_ID_AC_REFUSE_LOGIN         = 0x006a,
	PACKET_ID_SC_NOTIFY_BAN           = 0x0081,
	PACKET_ID_AC_ACK_HASH             = 0x01dc,
	PACKET_ID_AC_REFUSE_LOGIN_R2      = 0x083e,
};

/* Packets Structs */
#if !defined(sun) && (!defined(__NETBSD__) || __NetBSD_Version__ >= 600000000) // NetBSD 5 and Solaris don't like pragma pack but accept the packed attribute
#pragma pack(push, 1)
#endif // not NetBSD < 6 / Solaris

struct PACKET_CA_LOGIN {
	int16 PacketID;
	uint32 Version;
	char ID[24];
	char Passwd[24];
	uint8 clienttype;
} __attribute__((packed));

struct PACKET_CA_LOGIN2 {
	int16 PacketID;
	uint32 Version;
	char ID[24];
	uint8 PasswdMD5[16];
	uint8 clienttype;
} __attribute__((packed));

struct PACKET_CA_LOGIN3 {
	int16 PacketID;
	uint32 Version;
	char ID[24];
	uint8 PasswdMD5[16];
	uint8 clienttype;
	uint8 ClientInfo;
} __attribute__((packed));

struct PACKET_CA_LOGIN4 {
	int16 PacketID;
	uint32 Version;
	char ID[24];
	uint8 PasswdMD5[16];
	uint8 clienttype;
	char macData[13];
} __attribute__((packed));

struct PACKET_CA_LOGIN_PCBANG {
	int16 PacketID;
	uint32 Version;
	char ID[24];
	char Passwd[24];
	uint8 clienttype;
	char IP[16];
	char MacAdress[13];
} __attribute__((packed));

struct PACKET_CA_LOGIN_HAN {
	int16 PacketID;
	uint32 Version;
	char ID[24];
	char Passwd[24];
	uint8 clienttype;
	char m_szIP[16];
	char m_szMacAddr[13];
	uint8 isHanGameUser;
} __attribute__((packed));

struct PACKET_CA_SSO_LOGIN_REQ {
	int16 PacketID;
	int16 PacketLength;
	uint32 Version;
	uint8 clienttype;
	char ID[24];
	char Passwd[27];
	int8 MacAdress[17];
	char IP[15];
	char t1[];
} __attribute__((packed));

#if 0 // Unused
struct PACKET_CA_SSO_LOGIN_REQa {
	int16 PacketID;
	int16 PacketLength;
	uint32 Version;
	uint8 clienttype;
	char ID[24];
	char MacAddr[17];
	char IpAddr[15];
	char t1[];
} __attribute__((packed));
#endif // unused

struct PACKET_CA_CONNECT_INFO_CHANGED {
	int16 PacketID;
	char ID[24];
} __attribute__((packed));

struct PACKET_CA_EXE_HASHCHECK {
	int16 PacketID;
	uint8 HashValue[16];
} __attribute__((packed));

struct PACKET_CA_REQ_HASH {
	int16 PacketID;
} __attribute__((packed));

struct PACKET_CA_CHARSERVERCONNECT {
	int16 PacketID;
	char userid[24];
	char passwd[24];
	int32 unknow;
	int32 ip;
	int16 port;
	char name[20];
	int16 unknow2;
	int16 type;
	int16 new_;
} __attribute__((packed));

struct PACKET_SC_NOTIFY_BAN {
	int16 PacketID;
	uint8 ErrorCode;
} __attribute__((packed));

struct PACKET_AC_REFUSE_LOGIN {
	int16 PacketID;
	uint8 ErrorCode;
	char blockDate[20];
} __attribute__((packed));

struct PACKET_AC_REFUSE_LOGIN_R2 {
	int16 PacketID;
	uint32 ErrorCode;
	char blockDate[20];
} __attribute__((packed));

struct PACKET_AC_ACCEPT_LOGIN {
	int16 PacketType;
	int16 PacketLength;
	int32 AuthCode;
	uint32 AID;
	uint32 userLevel;
	uint32 lastLoginIP;
	char lastLoginTime[26];
	uint8 Sex;
	struct {
		uint32 ip;
		int16 port;
		char name[20];
		uint16 usercount;
		uint16 state;
		uint16 property;
	} ServerList[];
} __attribute__((packed));

struct PACKET_AC_ACK_HASH {
	int16 PacketID;
	int16 PacketLength;
	uint8 secret[];
} __attribute__((packed));

#if !defined(sun) && (!defined(__NETBSD__) || __NetBSD_Version__ >= 600000000) // NetBSD 5 and Solaris don't like pragma pack but accept the packed attribute
#pragma pack(pop)
#endif // not NetBSD < 6 / Solaris

/**
 * Login Client Interface Private Interface
 */
struct lclif_interface_private {
	void (*packetdb_loaddb)(void);
};

#endif // LOGIN_LCLIF_P_H
