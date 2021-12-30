	/*-
	* Free/Libre Near Field Communication (NFC) library
	*
	* Libnfc historical contributors:
	* Copyright (C) 2009      Roel Verdult
	* Copyright (C) 2009-2013 Romuald Conty
	* Copyright (C) 2010-2012 Romain Tartière
	* Copyright (C) 2010-2017 Philippe Teuwen
	* Copyright (C) 2012-2013 Ludovic Rousseau
	* See AUTHORS file for a more comprehensive list of contributors.
	* Additional contributors of this file:
	* Copyright (C) 2013-2017 Adam Laurie
	*
	* Redistribution and use in source and binary forms, with or without
	* modification, are permitted provided that the following conditions are met:
	*  1) Redistributions of source code must retain the above copyright notice,
	*  this list of conditions and the following disclaimer.
	*  2 )Redistributions in binary form must reproduce the above copyright
	*  notice, this list of conditions and the following disclaimer in the
	*  documentation and/or other materials provided with the distribution.
	*
	* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	* POSSIBILITY OF SUCH DAMAGE.
	*
	* Note that this license only applies on the examples, NFC library itself is under LGPL
	*
	*/

	/**
	 * @file nfc-mfultralight.c
	 * @brief MIFARE Ultralight dump/restore tool
	 */

	#ifdef HAVE_CONFIG_H
	#  include "config.h"
	#endif // HAVE_CONFIG_H

	#include <stdio.h>
	#include <stdlib.h>
	#include <stdint.h>
	#include <stddef.h>
	#include <stdbool.h>

	#include <string.h>
	#include <ctype.h>

	#include <nfc/nfc.h>

	#include "nfc-utils.h"
	#include "mifare.h"

	#define MAX_TARGET_COUNT 16
	#define MAX_UID_LEN 10

	#define EV1_NONE 0
	#define EV1_UL11 1
	#define EV1_UL21 2

	static nfc_device *pnd;
	static nfc_target nt;
	static mifare_param mp;
	static mifareul_ev1_mf0ul21_tag mtDump; // use the largest tag type for internal storage
	static uint32_t uiBlocks = 0x10;
	static uint32_t uiReadPages = 0;
	static uint8_t iPWD[4] = { 0x0 };
	static uint8_t iPACK[2] = { 0x0 };
	static uint8_t iEV1Type = EV1_NONE;

	// special unlock command
	uint8_t  abtUnlock1[1] = { 0x40 };
	uint8_t  abtUnlock2[1] = { 0x43 };

	// EV1 commands
	uint8_t  abtEV1[3] = { 0x60, 0x00, 0x00 };
	uint8_t  abtPWAuth[7] = { 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	//Halt command
	uint8_t  abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };

	#define MAX_FRAME_LEN 264

	static uint8_t abtRx[MAX_FRAME_LEN];
	static int szRxBits;
	static int szRx;

	static const nfc_modulation nmMifare = {
		.nmt = NMT_ISO14443A,
		.nbr = NBR_106,
	};

	int _silent_mode = 0;
	int write_stdout( const char * format, ... ) {
		if (_silent_mode != 0)
			return 0;

		va_list args;
		va_start (args, format);
		int n = vprintf (format, args);
		va_end (args);

		return n;
	}

	static void
	print_success_or_failure(bool bFailure, uint32_t *uiOkCounter, uint32_t *uiFailedCounter)
	{
		write_stdout("%c", (bFailure) ? 'f' : '.');
		if (uiOkCounter)
			*uiOkCounter += (bFailure) ? 0 : 1;
		if (uiFailedCounter)
			*uiFailedCounter += (bFailure) ? 1 : 0;
	}

	static  bool
	read_card(void)
	{
		uint32_t page;
		bool    bFailure = false;
		uint32_t uiFailedPages = 0;

		write_stdout("Reading %d pages |", uiBlocks);

		for (page = 0; page < uiBlocks; page += 4) {
			// Try to read out the data block
			if (nfc_initiator_mifare_cmd(pnd, MC_READ, page, &mp)) {
			memcpy(mtDump.amb[page / 4].mbd.abtData, mp.mpd.abtData, uiBlocks - page < 4 ? (uiBlocks - page) * 4 : 16);
			} else {
			bFailure = true;
			}
			for (uint8_t i = 0; i < (uiBlocks - page < 4 ? uiBlocks - page : 4); i++) {
			print_success_or_failure(bFailure, &uiReadPages, &uiFailedPages);
			}
		}
		write_stdout("|\n");
		write_stdout("Done, %d of %d pages read (%d pages failed).\n", uiReadPages, uiBlocks, uiFailedPages);
		fflush(stdout);

		// copy EV1 secrets to dump data
		switch (iEV1Type) {
			case EV1_UL11:
			memcpy(mtDump.amb[4].mbc11.pwd, iPWD, 4);
			memcpy(mtDump.amb[4].mbc11.pack, iPACK, 2);
			break;
			case EV1_UL21:
			memcpy(mtDump.amb[9].mbc21a.pwd, iPWD, 4);
			memcpy(mtDump.amb[9].mbc21b.pack, iPACK, 2);
			break;
			case EV1_NONE:
			default:
			break;
		}

		return (!bFailure);
	}

	static  bool
	transmit_bits(const uint8_t *pbtTx, const size_t szTxBits)
	{
		// Transmit the bit frame command, we don't use the arbitrary parity feature
		if ((szRxBits = nfc_initiator_transceive_bits(pnd, pbtTx, szTxBits, NULL, abtRx, sizeof(abtRx), NULL)) < 0)
			return false;

		return true;
	}


	static  bool
	transmit_bytes(const uint8_t *pbtTx, const size_t szTx)
	{
		if ((szRx = nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), 0)) < 0)
			return false;

		return true;
	}

	static bool
	raw_mode_start(void)
	{
		// Configure the CRC
		if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false) < 0) {
			nfc_perror(pnd, "nfc_configure");
			return false;
		}
		// Use raw send/receive methods
		if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
			nfc_perror(pnd, "nfc_configure");
			return false;
		}
		return true;
	}

	static bool
	raw_mode_end(void)
	{
		// reset reader
		// Configure the CRC
		if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, true) < 0) {
			nfc_perror(pnd, "nfc_device_set_property_bool");
			return false;
		}
		// Switch off raw send/receive methods
		if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, true) < 0) {
			nfc_perror(pnd, "nfc_device_set_property_bool");
			return false;
		}
		return true;
	}

	static bool
	get_ev1_version(void)
	{
		if (!raw_mode_start())
			return false;
		iso14443a_crc_append(abtEV1, 1);
		if (!transmit_bytes(abtEV1, 3)) {
			raw_mode_end();
			return false;
		}
		if (!raw_mode_end())
			return false;
		if (!szRx)
			return false;
		return true;
	}

	static bool
	ev1_load_pwd(uint8_t target[4], const char *pwd)
	{
		unsigned int tmp[4];
		if (sscanf(pwd, "%2x%2x%2x%2x", &tmp[0], &tmp[1], &tmp[2], &tmp[3]) != 4)
			return false;
		target[0] = tmp[0];
		target[1] = tmp[1];
		target[2] = tmp[2];
		target[3] = tmp[3];
		return true;
	}

	static bool
	ev1_pwd_auth(uint8_t *pwd)
	{
		if (!raw_mode_start())
			return false;
		memcpy(&abtPWAuth[1], pwd, 4);
		iso14443a_crc_append(abtPWAuth, 5);
		if (!transmit_bytes(abtPWAuth, 7))
			return false;
		if (!raw_mode_end())
			return false;
		return true;
	}

	static bool
	unlock_card(void)
	{
		if (!raw_mode_start())
			return false;
		iso14443a_crc_append(abtHalt, 2);
		transmit_bytes(abtHalt, 4);
		// now send unlock
		if (!transmit_bits(abtUnlock1, 7)) {
			return false;
		}
		if (!transmit_bytes(abtUnlock2, 1)) {
			return false;
		}

		if (!raw_mode_end())
			return false;
		return true;
	}

	static bool check_magic()
	{
		bool     bFailure = false;
		int      uid_data;

		for (uint32_t page = 0; page <= 1; page++) {
			// Show if the readout went well
			if (bFailure) {
			// When a failure occured we need to redo the anti-collision
			if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
				ERR("tag was removed");
				return false;
			}
			bFailure = false;
			}

			uid_data = 0x00000000;

			memcpy(mp.mpd.abtData, &uid_data, sizeof uid_data);
			memset(mp.mpd.abtData + 4, 0, 12);

			//Force the write without checking for errors - otherwise the writes to the sector 0 seem to complain
			nfc_initiator_mifare_cmd(pnd, MC_WRITE, page, &mp);
		}

		//Check that the ID is now set to 0x000000000000
		if (nfc_initiator_mifare_cmd(pnd, MC_READ, 0, &mp)) {
			//write_stdout("%u", mp.mpd.abtData);
			bool result = true;
			for (int i = 0; i <= 7; i++) {
			if (mp.mpd.abtData[i] != 0x00) result = false;
			}

			if (result) {
			return true;
			}

		}

		//Initially check if we can unlock via the MF method
		if (unlock_card()) {
			return true;
		} else {
			return false;
		}

	}

	static  bool
	write_card(bool write_otp, bool write_lock, bool write_uid)
	{
		uint32_t uiBlock = 0;
		bool    bFailure = false;
		uint32_t uiWrittenPages = 0;
		uint32_t uiSkippedPages = 0;
		uint32_t uiFailedPages = 0;

		char    buffer[BUFSIZ];


		write_stdout("Writing %d pages |", uiBlocks);
		/* We may need to skip 2 first pages. */
		if (!write_uid) {
			write_stdout("ss");
			uiSkippedPages = 2;
		} else {
			if (!check_magic()) {
			write_stdout("\nUnable to unlock card - are you sure the card is magic?\n");
			return false;
			}
		}

		for (uint32_t page = uiSkippedPages; page < uiBlocks; page++) {
			if ((page == 0x2) && (!write_lock)) {
			write_stdout("s");
			uiSkippedPages++;
			continue;
			}
			if ((page == 0x3) && (!write_otp)) {
			write_stdout("s");
			uiSkippedPages++;
			continue;
			}
			// Check if the previous readout went well
			if (bFailure) {
			// When a failure occured we need to redo the anti-collision
			if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
				ERR("tag was removed");
				return false;
			}
			bFailure = false;
			}
			// For the Mifare Ultralight, this write command can be used
			// in compatibility mode, which only actually writes the first
			// page (4 bytes). The Ultralight-specific Write command only
			// writes one page at a time.
			uiBlock = page / 4;
			memcpy(mp.mpd.abtData, mtDump.amb[uiBlock].mbd.abtData + ((page % 4) * 4), 4);
			memset(mp.mpd.abtData + 4, 0, 12);
			if (!nfc_initiator_mifare_cmd(pnd, MC_WRITE, page, &mp))
			bFailure = true;
			print_success_or_failure(bFailure, &uiWrittenPages, &uiFailedPages);
		}
		write_stdout("|\n");
		write_stdout("Done, %d of %d pages written (%d pages skipped, %d pages failed).\n", uiWrittenPages, uiBlocks, uiSkippedPages, uiFailedPages);

		return true;
	}

	unsigned char _pages[] = {
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x03,0x00,0xD1,0x01, 0x00,0x55,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
	};

	char _sUrl[1024];

	static  bool
	read_card2(void)
	{
		uint32_t page;
		bool    bFailure = false;
		uint32_t uiFailedPages = 0;

		memset(_sUrl,0,1024);
		write_stdout("Reading %d pages |", uiBlocks);

		for (page = 0; page < uiBlocks; page += 4) {
			// Try to read out the data block
			if (nfc_initiator_mifare_cmd(pnd, MC_READ, page, &mp)) {
				memcpy(mtDump.amb[page / 4].mbd.abtData, mp.mpd.abtData, uiBlocks - page < 4 ? (uiBlocks - page) * 4 : 16);				
			} else {
				bFailure = true;
			}

			for (uint8_t i = 0; i < (uiBlocks - page < 4 ? uiBlocks - page : 4); i++) {
				print_success_or_failure(bFailure, &uiReadPages, &uiFailedPages);
			}
		}
		write_stdout("|\n");
		write_stdout("Done, %d of %d pages read (%d pages failed).\n", uiReadPages, uiBlocks, uiFailedPages);
		fflush(stdout);

		// copy EV1 secrets to dump data
		switch (iEV1Type) {
			case EV1_UL11:
				memcpy(mtDump.amb[4].mbc11.pwd, iPWD, 4);
				memcpy(mtDump.amb[4].mbc11.pack, iPACK, 2);
				break;
			case EV1_UL21:
				memcpy(mtDump.amb[9].mbc21a.pwd, iPWD, 4);
				memcpy(mtDump.amb[9].mbc21b.pack, iPACK, 2);
				break;
			case EV1_NONE:
			default:
				break;
		}

		if (bFailure == false) {

			memcpy(_pages,&mtDump,uiReadPages * 4);

			unsigned char data_len = _pages[20] - 1;
			unsigned char uri_id_code = _pages[22];
			_pages[23+data_len] = 0x00;
			
			if (uri_id_code == 0x02) 
			{				
				strcpy(_sUrl,"https://www.");
			}
			else if (uri_id_code == 0x04)
			{
				strcpy(_sUrl,"https://");
			}
			
			strcat(_sUrl,_pages+23);
						 
			write_stdout("Readed url: %s", _sUrl);			
		}

		return (bFailure == false);
	}

	static  bool
	write_card2()
	{
		uint32_t uiBlock = 0;
		bool    bFailure = false;
		uint32_t uiWrittenPages = 0;
		uint32_t uiSkippedPages = 0;
		uint32_t uiFailedPages = 0;

		char    buffer[BUFSIZ];
		char* purl = _sUrl;

		write_stdout("Writing url %s\n", _sUrl);

		unsigned char data_len = 0;
		unsigned char uri_id_code = 0;
		if (strncmp(_sUrl,"https://www.",strlen("https://www."))==0) 
		{
			uri_id_code = 0x02;
			purl = _sUrl + strlen("https://www.");
			data_len = (unsigned char) strlen(purl);
		} 
		else if (strncmp(_sUrl,"https://",strlen("https://"))==0) 
		{
			uri_id_code = 0x04;
			purl = _sUrl + strlen("https://");
			data_len = (unsigned char) strlen(purl);
		}

		memcpy(_pages+23,purl,data_len);
		write_stdout("Check Writing url %s\n", _pages+23);
		_pages[17] = data_len + 1 + 4;
		_pages[20] = data_len + 1;
		_pages[22] = uri_id_code;
		_pages[23+data_len] = 0xFE;

		for (uint32_t page = 4; page < uiBlocks; page++) {

			// Check if the previous readout went well
			if (bFailure) {
				// When a failure occured we need to redo the anti-collision
				if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
					ERR("tag was removed");
					return false;
				}
				bFailure = false;
			}

			// For the Mifare Ultralight, this write command can be used
			// in compatibility mode, which only actually writes the first
			// page (4 bytes). The Ultralight-specific Write command only
			// writes one page at a time.
			uiBlock = page / 4;
			memcpy(mp.mpd.abtData, _pages + (page * 4), 4);
			memset(mp.mpd.abtData + 4, 0, 12);
			if (!nfc_initiator_mifare_cmd(pnd, MC_WRITE, page, &mp))
				bFailure = true;
			print_success_or_failure(bFailure, &uiWrittenPages, &uiFailedPages);
		}
		write_stdout("|\n");
		write_stdout("Done, %d of %d pages written (%d pages skipped, %d pages failed).\n", uiWrittenPages, uiBlocks, uiSkippedPages, uiFailedPages);

		return bFailure==false;
	}

	bool list_nfc_devices(nfc_context *context) 
	{
		const MAX_DEVICE_COUNT = 1024;
		nfc_connstring connstrings[MAX_DEVICE_COUNT];
		size_t szDeviceFound = nfc_list_devices(context, connstrings, MAX_DEVICE_COUNT);

		if (szDeviceFound == 0) {
			write_stdout("No NFC device found.\n");
			if (_silent_mode != 0)
				printf("[ ]");

			return true;
		}

		write_stdout("%d NFC device(s) found:\n", (int)szDeviceFound);
		char *strinfo = NULL;
		if (_silent_mode != 0)
			printf("[\n");
		for (int i = 0; i < szDeviceFound; i++) {
			pnd = nfc_open(context, connstrings[i]);
			if (pnd != NULL) {
				write_stdout("- %s:\n    %s\n", nfc_device_get_name(pnd), nfc_device_get_connstring(pnd));
				if (_silent_mode != 0)
					printf("{ \"name\": \"%s\",  \"connection_string\": \"%s\"}\n", nfc_device_get_name(pnd),nfc_device_get_connstring(pnd),(i!=szDeviceFound-1?",":""));
				nfc_close(pnd);
			} else {
				write_stdout("nfc_open failed for %s\n", connstrings[i]);
			}
		}

		if (_silent_mode != 0)
			printf("]");

		return true;
	}


	char _chip_uuid[1024];
	static int list_passive_targets(nfc_device *_pnd)
	{
		int res = 0;

		nfc_target ant[MAX_TARGET_COUNT];

		if (nfc_initiator_init(_pnd) < 0) {
			return -EXIT_FAILURE;
		}

		memset(_chip_uuid,0,1024);
		if ((res = nfc_initiator_list_passive_targets(_pnd, nmMifare, ant, MAX_TARGET_COUNT)) >= 0) {
			int i;

			if (res > 0)
				write_stdout("%d ISO14443A passive target(s) found:\n", res);

			for (i = 0; i < res; i++) {
				size_t  szPos;

				write_stdout("\t");
				int pos = 0;
				for (szPos = 0; szPos < ant[i].nti.nai.szUidLen; szPos++) {
					//write_stdout("%02x", ant[i].nti.nai.abtUid[szPos]);
					sprintf(_chip_uuid+pos,"%02x", ant[i].nti.nai.abtUid[szPos]);
					pos += 2;
				}
				write_stdout("%s\n",_chip_uuid);
			}

		}

		return 0;
	}

	static size_t str_to_uid(const char *str, uint8_t *uid)
	{
		uint8_t i;

		memset(uid, 0x0, MAX_UID_LEN);
		i = 0;
		while ((*str != '\0') && ((i >> 1) < MAX_UID_LEN)) {
			char nibble[2] = { 0x00, '\n' }; /* for strtol */

			nibble[0] = *str++;
			if (isxdigit(nibble[0])) {
			if (isupper(nibble[0]))
				nibble[0] = tolower(nibble[0]);
			uid[i >> 1] |= strtol(nibble, NULL, 16) << ((i % 2) ? 0 : 4) & ((i % 2) ? 0x0f : 0xf0);
			i++;
			}
		}
		return i >> 1;
	}

	static void
	print_usage(const char *argv[])
	{
		printf("Usage: %s r|w <URL> [OPTIONS]\n", argv[0]);
		printf("Arguments:\n");  
		printf("\tl                   - List nfc devices\n");
		printf("\tr                   - Perform read\n");
		printf("\tw <URL>             - Perform write\n");  
		printf("\t-json               - Output only needed info in json mode");
	}

	int
	main(int argc, const char *argv[])
	{
		int     iAction = 0;
		uint8_t iDumpSize = sizeof(mifareul_tag);
		uint8_t iUID[MAX_UID_LEN] = { 0x0 };
		size_t  szUID = 0;
		bool    bOTP = false;
		bool    bLock = false;
		bool    bUID = false;
		bool    bPWD = false;
		bool    bPart = false;
		FILE   *pfDump;
		

		if (argc < 2) {
			print_usage(argv);
			exit(EXIT_FAILURE);
		}

		DBG("\nChecking arguments and settings\n");
		memset(_sUrl,0,1024);
		memset(_chip_uuid,0,1024);

		// Get commandline options
		for (int arg = 1; arg < argc; arg++) {
			if (0 == strcmp(argv[arg], "w")) {
				if (argc < 2) {
					print_usage(argv);
					exit(EXIT_FAILURE);
				}

				iAction = 1;
				strcpy(_sUrl,argv[arg+1]);								
			} else if (0 == strcmp(argv[arg], "r")) {
				iAction = 2;
			} else if(0 == strcmp(argv[arg], "l")) {
				iAction = 3;
			}

			if (0 == strcmp(argv[arg], "-json")) {
				_silent_mode = 1;
			}
		}

		nfc_context *context;
		nfc_init(&context);
		if (context == NULL) {
			ERR("Unable to init libnfc (malloc)");
			exit(EXIT_FAILURE);
		}

		if (iAction == 3) {
			list_nfc_devices(context);
			nfc_exit(context);
			exit(EXIT_SUCCESS);
		}

		// Try to open the NFC device
		pnd = nfc_open(context, NULL);
		if (pnd == NULL) {
			ERR("Error opening NFC device");
			nfc_exit(context);
			exit(EXIT_FAILURE);
		}
		write_stdout("NFC device: %s opened\n", nfc_device_get_name(pnd));

		if (list_passive_targets(pnd)) {
			nfc_perror(pnd, "nfc_device_set_property_bool");
			nfc_close(pnd);
			nfc_exit(context);
			exit(EXIT_FAILURE);
		}

		if (nfc_initiator_init(pnd) < 0) {
			nfc_perror(pnd, "nfc_initiator_init");
			nfc_close(pnd);
			nfc_exit(context);
			exit(EXIT_FAILURE);
		}

		// Let the device only try once to find a tag
		if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0) {
			nfc_perror(pnd, "nfc_device_set_property_bool");
			nfc_close(pnd);
			nfc_exit(context);
			exit(EXIT_FAILURE);
		}

		// Try to find a MIFARE Ultralight tag
		if (nfc_initiator_select_passive_target(pnd, nmMifare, (szUID) ? iUID : NULL, szUID, &nt) <= 0) {

			if (_silent_mode != 0) {
				printf("{ \"chip_uuid\": \"%s\", \"url\": \"%s\" }", "NOT_FOUND", "");
				nfc_close(pnd);
				nfc_exit(context);
				exit(EXIT_SUCCESS);
			}

			ERR("no tag was found\n");
			nfc_close(pnd);
			nfc_exit(context);
			exit(EXIT_FAILURE);
		}

		// Test if we are dealing with a MIFARE compatible tag
		if (nt.nti.nai.abtAtqa[1] != 0x44) {
			ERR("tag is not a MIFARE Ultralight card\n");
			nfc_close(pnd);
			nfc_exit(context);
			exit(EXIT_FAILURE);
		}
		// Get the info from the current tag
		write_stdout("Using MIFARE Ultralight card with UID: ");
		size_t  szPos;
		for (szPos = 0; szPos < nt.nti.nai.szUidLen; szPos++) {
			write_stdout("%02x", nt.nti.nai.abtUid[szPos]);
		}
		write_stdout("\n");

		// test if tag is EV1
		if (get_ev1_version()) {
			if (!bPWD)
				write_stdout("Tag is EV1 - PASSWORD may be required\n");
			write_stdout("EV1 storage size: ");
			if (abtRx[6] == 0x0b) {
				write_stdout("48 bytes\n");
				uiBlocks = 0x14;
				iEV1Type = EV1_UL11;
				iDumpSize = sizeof(mifareul_ev1_mf0ul11_tag);
			} else if (abtRx[6] == 0x0e) {
				write_stdout("128 bytes\n");
				uiBlocks = 0x29;
				iEV1Type = EV1_UL21;
				iDumpSize = sizeof(mifareul_ev1_mf0ul21_tag);
			} else
				write_stdout("unknown!\n");
		} else {
			// re-init non EV1 tag
			if (nfc_initiator_select_passive_target(pnd, nmMifare, (szUID) ? iUID : NULL, szUID, &nt) <= 0) {
				ERR("no tag was found\n");
				nfc_close(pnd);
				nfc_exit(context);
				exit(EXIT_FAILURE);
			}
		}

		// EV1 login required
		if (bPWD) {
			write_stdout("Authing with PWD: %02x%02x%02x%02x ", iPWD[0], iPWD[1], iPWD[2], iPWD[3]);
			if (!ev1_pwd_auth(iPWD)) {
				write_stdout("\n");
				ERR("AUTH failed!\n");
				exit(EXIT_FAILURE);
			} else {
				write_stdout("Success - PACK: %02x%02x\n", abtRx[0], abtRx[1]);
				memcpy(iPACK, abtRx, 2);
			}
		}

		memset(&mtDump, 0x00, sizeof(mtDump));

		if (iAction == 1) {
			if (write_card2() == false) {
				ERR("Warning! Write failed!\n");
				nfc_close(pnd);
				nfc_exit(context);
				exit(EXIT_FAILURE);
			}
			iAction = 2;	//fa eseguire la lettura
		}

		if (iAction == 2) {
			if (read_card2() == false) {
				ERR("Warning! Read failed!\n");
				nfc_close(pnd);
				nfc_exit(context);
				exit(EXIT_FAILURE);
			}

			if (_silent_mode != 0) {
				printf("{ \"chip_uuid\": \"%s\", \"url\": \"%s\" }", _chip_uuid, _sUrl);
			}		
		}

		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_SUCCESS);
	}
