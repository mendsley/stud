/* Copyright 2015 Matthew Endsley */

#include "slist.h"

#include <assert.h>
#include <pthread.h>

struct slist_node {
	struct slist_node* next;
};

void slist_init(struct slist* sl) {
	pthread_mutex_init(&sl->lock, NULL);
	sl->head = 0;
}

void slist_destroy(struct slist* sl) {
	pthread_mutex_destroy(&sl->lock);
	assert(sl->head == 0);
}

void slist_push(struct slist* sl, void* p) {
	pthread_mutex_lock(&sl->lock);
	struct slist_node* n = (struct slist_node*)p;
	n->next = sl->head;
	sl->head = n;
	pthread_mutex_unlock(&sl->lock);
}

void* slist_pop(struct slist* sl) {
	struct slist_node* n = 0;

	pthread_mutex_lock(&sl->lock);
	n = sl->head;
	if (n) {
		sl->head = n->next;
	}
	pthread_mutex_unlock(&sl->lock);

	return n;
}
