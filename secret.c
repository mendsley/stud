/* Copyright 2015-2016 Matthew Endsley */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <crypto_secretbox.h>

#include "secret.h"

int secret_genkey_tostdout() {
	uint8_t key[crypto_secretbox_KEYBYTES];
	BIO *out;
	BUF_MEM *encoded_key;

	if (1 != RAND_bytes(key, sizeof(key))) {
		return 1;
	}

	out = BIO_new(BIO_f_base64());
	BIO_set_flags(out, BIO_FLAGS_BASE64_NO_NL);
	out = BIO_push(out, BIO_new(BIO_s_mem()));
	BIO_write(out, key, sizeof(key));
	if (BIO_flush(out) < 1) {
		BIO_free_all(out);
		return 1;
	}

	BIO_get_mem_ptr(out, &encoded_key);

	printf("%.*s\n", (int)encoded_key->length, encoded_key->data);

	BIO_free_all(out);
	return 0;
}

int secret_encrypt_tostdout(const char* path) {
	BIO* bio;
	FILE* fp;
	unsigned char* key;
	int nkey;
	unsigned char* file_data;
	unsigned char* encrypted_file_data;
	int nfile_data;
	BUF_MEM* encoded_keycert;
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	const char* encoded_key = getenv("STUD_SECRETBOX_KEY");
	const size_t nencoded_key = strlen(encoded_key);

	if (!encoded_key) {
		fprintf(stderr, "No STUD_SECRETBOX_KEY specified\n");
		return 1;
	}

	// decode key
	bio = BIO_new(BIO_f_base64());
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	bio = BIO_push(bio, BIO_new_mem_buf((void*)encoded_key, (int)nencoded_key));

	key = malloc(nencoded_key);
	if (!key) {
		BIO_free_all(bio);
		return 1;
	}

	nkey = BIO_read(bio, key, nencoded_key);
	BIO_free_all(bio);
	if (nkey != crypto_secretbox_KEYBYTES) {
		fprintf(stderr, "Failed to decode STUD_SECRETBOX_KEY\n");
		free(key);
		return 1;
	}

	// generate a nonce
	if (1 != RAND_bytes(nonce, sizeof(nonce))) {
		fprintf(stderr, "Failed to generate a nonce.\n");
		free(key);
		return 1;
	}

	// read file
	fp = fopen(path, "rb");
	if (!fp) {
		fprintf(stderr, "Failed to open %s\n", path);
		free(key);
		return 1;
	}

	fseek(fp, 0, SEEK_END);
	nfile_data = (int)ftell(fp);
	fseek(fp, 0, SEEK_SET);

	file_data = malloc(nfile_data + crypto_secretbox_ZEROBYTES);
	memset(file_data, 0, crypto_secretbox_ZEROBYTES);
	if (1 != fread(file_data+crypto_secretbox_ZEROBYTES, nfile_data, 1, fp)) {
		fprintf(stderr, "Failed to read %s\n", path);
		free(file_data);
		fclose(fp);
		free(key);
		return 1;
	}
	fclose(fp);

	// encrypt file data
	encrypted_file_data = malloc(nfile_data+crypto_secretbox_ZEROBYTES);
	if (0 != crypto_secretbox(encrypted_file_data, file_data, nfile_data+crypto_secretbox_ZEROBYTES, nonce, key)) {
		free(encrypted_file_data);
		free(file_data);
		free(key);
		return 1;
	}
	free(file_data);
	free(key);

	// encode encrypted keycert
	bio = BIO_new(BIO_f_base64());
	//BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	bio = BIO_push(bio, BIO_new(BIO_s_mem()));
	BIO_write(bio, nonce, sizeof(nonce));
	BIO_write(bio, encrypted_file_data+crypto_secretbox_ZEROBYTES, nfile_data);
	free(encrypted_file_data);
	if (BIO_flush(bio) < 1) {
		BIO_free_all(bio);
		return 1;
	}

	BIO_get_mem_ptr(bio, &encoded_keycert);
	printf("%.*s\n", (int)encoded_keycert->length, encoded_keycert->data);
	BIO_free_all(bio);
	return 0;
}
