/* Copyright 2015 Matthew Endsley */

#include <pthread.h>

struct slist_node;

struct slist {
	pthread_mutex_t lock;
	struct slist_node* head;
};

void slist_init(struct slist* sl);
void slist_deestroy(struct slist* sl);
void slist_push(struct slist* sl, void* p);
void* slist_pop(struct slist* sl);
