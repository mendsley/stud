/* Copyright 2015 Matthew Endsley */

#define BUFFERCHAIN_BLOCK_SIZE 1024

struct bufferchain_node {
	struct bufferchain_node* next;
	char data[BUFFERCHAIN_BLOCK_SIZE];
};

struct bufferchain {
	struct bufferchain_node* read;
	struct bufferchain_node* write;
	int wcommitted;
	int rconsumed;
};

void bufferchain_startup();
void bufferchain_init(struct bufferchain* bc);
void bufferchain_destroy(struct bufferchain* bc);
void* bufferchain_get_writeptr(struct bufferchain* bc, int* sz);
void bufferchain_commit_write(struct bufferchain* bc, int sz);
void bufferchain_write(struct bufferchain* bc, const void* ptr, int sz);
void* bufferchain_get_readptr(struct bufferchain* bc);
void bufferchain_commit_read(struct bufferchain* bc, int sz);
int bufferchain_readable(struct bufferchain* bc);
