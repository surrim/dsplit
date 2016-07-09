/* Copyright surrim 2015-2016
 *
 * This file is part of dsplit.
 *
 * dsplit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dsplit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dsplit.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dsplit.h"

#include <gcrypt.h>
#include <inttypes.h>

static const char TMP_FILE_NAME[] = "tmp";
static const uint16_t PRIME = 21613; // "god" in base64
static const uint16_t UNDO_PRIME = 41985; // PRIME ** 256 % 65536
static const int HASH_ALGORITHM = GCRY_MD_SHA256;
static const size_t HASH_BITS = 256;

static void split(gcry_md_hd_t md, FILE *chunk, const char *directory) {
	const size_t HASH_BYTES = (HASH_BITS + 7) / 8;
	uint8_t *hashed = gcry_md_read(md, HASH_ALGORITHM);
	char name[2 * HASH_BYTES + 1];
	for (size_t i = 0; i != HASH_BYTES; i++) {
		const char HEX[] = "0123456789abcdef";
		name[2 * i]     = HEX[hashed[i] >> 4];
		name[2 * i + 1] = HEX[hashed[i] & 15];
	}
	name[2 * HASH_BYTES] = '\0';
	if (directory) {
		char fileName[strlen(directory) + 1 + 2 * HASH_BYTES + 1];
		sprintf(fileName, "%s/%s", directory, name);
		remove(fileName);
		rename(TMP_FILE_NAME, fileName);
	} else {
		remove(name);
		rename(TMP_FILE_NAME, name);
	}
	gcry_md_reset(md);
	freopen(TMP_FILE_NAME, "wb", chunk);
	printf("%s\n", name);
}

static void openFile(gcry_md_hd_t *md, FILE **chunk) {
	gcry_md_open(md, HASH_ALGORITHM, 0);
	*chunk = fopen(TMP_FILE_NAME, "wb");
}

static void updateFile(gcry_md_hd_t md, FILE *chunk, const void *data, size_t dataSize) {
	gcry_md_write(md, data, dataSize);
	fwrite(data, 1, dataSize, chunk);
}

static void closeFile(gcry_md_hd_t md, FILE *chunk) {
	gcry_md_close(md);
	fclose(chunk);
	remove(TMP_FILE_NAME);
}

void dsplit(FILE *file, const char *directory) {
	gcry_md_hd_t md;
	FILE *chunk;
	openFile(&md, &chunk);

	uint8_t buffer0[256] = {};
	uint8_t buffer1[256] = {};

	uint8_t *oldBuffer = buffer0;
	uint8_t *newBuffer = buffer1;
	uint16_t hash = 0;
	while (1) {
		int readBytes = fread(newBuffer, 1, 256, file);
		size_t begin = 0;
		for (int i = 0; i < readBytes; i++) {
			uint8_t oldByte = oldBuffer[i];
			uint8_t newByte = newBuffer[i];
			hash = hash * PRIME - UNDO_PRIME * oldByte + newByte;
			if (hash == 0xFFFF) {
				updateFile(md, chunk, newBuffer + begin, i - begin + 1);
				begin = i + 1;
				split(md, chunk, directory);
			}
		}
		updateFile(md, chunk, newBuffer + begin, readBytes - begin);
		if (readBytes != 256) {
			break;
		}
		uint8_t *tmpBuffer = newBuffer;
		newBuffer = oldBuffer;
		oldBuffer = tmpBuffer;
	}
	if (ftell(chunk)) {
		split(md, chunk, directory);
	}
	closeFile(md, chunk);
}
