/* dlfcn.h/-ldl stubs */
#include <stdlib.h>

void *dlopen(const char* filename, int flag) {
	(void)filename;
	(void)flag;
	return NULL;
}

char *dlerror() {
	return NULL;
}

void *dlsym(void* handle, const char* symbol) {
	(void)handle;
	(void)symbol;
	abort();
	return NULL;
}

int dlclose(void* handle) {
	(void)handle;
	return 0;
}

#ifdef _GNU_SOURCE
#include <dlfcn.h>

int dladdr(const void* addr, Dl_info* info) {
	(void)addr;
	(void)info;
	abort();
	return 0;
}
#endif
