#include <stdio.h>
#include <sys/time.h>

int main() {
	struct timeval tv;
	gettimeofday(&tv, 0);
	printf("time is %ld\n", tv.tv_sec);
	return 0;
}