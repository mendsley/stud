/* Copyright 2015 Matthew Endsley */

#include "bufferchain.h"
#include "slist.h"

#include <stdlib.h>
#include <string.h>

static struct slist g_buffer_freelist;

static struct bufferchain_node* get_block() {
	struct bufferchain_node* n = slist_pop(&g_buffer_freelist);
	if (!n) {
		n = malloc(sizeof(struct bufferchain_node));
	}

	n->next = 0;
	return n;
}

static void put_block(struct bufferchain_node* n) {
	slist_push(&g_buffer_freelist, n);
}


void bufferchain_startup() {
	slist_init(&g_buffer_freelist);
}

void bufferchain_init(struct bufferchain* bc) {
	bc->read = 0;
	bc->write = 0;
	bc->wcommitted = 0;
	bc->rconsumed = 0;
}

void bufferchain_destroy(struct bufferchain* bc) {
	struct bufferchain_node* n = bc->read;
	while (n) {
		struct bufferchain_node* d = n;
		n = n->next;
		put_block(d);
	}

	bc->read = 0;
	bc->write = 0;
}

void *bufferchain_get_writeptr(struct bufferchain* bc, int* sz) {
	/* do we need to allocate a new block? */
	if (bc->write == 0 || bc->wcommitted == BUFFERCHAIN_BLOCK_SIZE) {
		struct bufferchain_node* n = get_block();
		if (bc->write) {
			bc->write->next = n;
		} else {
			bc->read = n;
		}
		bc->write = n;

		bc->wcommitted = 0;
	}

	*sz = BUFFERCHAIN_BLOCK_SIZE - bc->wcommitted;
	return bc->write->data + bc->wcommitted;
}

void bufferchain_commit_write(struct bufferchain* bc, int sz) {
	bc->wcommitted += sz;
}

void bufferchain_write(struct bufferchain* bc, const void* ptr, int sz) {
	const char* in = (const char*)ptr;
	while (sz > 0) {
		int wsz;
		void* out = bufferchain_get_writeptr(bc, &wsz);
		if (wsz > sz) {
			wsz = sz;
		}

		memcpy(out, in, wsz);
		sz -= wsz;
		bufferchain_commit_write(bc, wsz);
	}
}

void* bufferchain_get_readptr(struct bufferchain* bc) {
	if (bc->read) {
		return bc->read->data + bc->rconsumed;
	} else {
		return 0;
	}
}

void bufferchain_commit_read(struct bufferchain* bc, int sz) {
	bc->rconsumed += sz;
	if (bc->read == bc->write && bc->rconsumed == bc->wcommitted) {
		bc->rconsumed = 0;
		bc->wcommitted = 0;
	} else if (bc->rconsumed == BUFFERCHAIN_BLOCK_SIZE) {
		struct bufferchain_node* d = bc->read;
		bc->read = bc->read->next;
		put_block(d);
		bc->rconsumed = 0;
	}
}

int bufferchain_readable(struct bufferchain* bc) {
	if (!bc->read) {
		return 0;
	} else if (bc->read == bc->write) {
		return bc->wcommitted - bc->rconsumed;
	} else {
		return BUFFERCHAIN_BLOCK_SIZE - bc->rconsumed;
	}
}
