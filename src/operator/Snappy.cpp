#include <snappy.h>

using namespace std;

#define MAX_THREAD 100
#define MAX_LEN 1500

unsigned char inp[MAX_THREAD * MAX_LEN + 10];
unsigned short outp[MAX_THREAD * MAX_LEN + 10];

#define rainbow 56
#define time_spend time_taken / rainbow;


int compress(unsigned char* src, unsigned short* res, int len)
{
	snappy::Compress(src, len, res);
	
}
 
int decompress(unsigned short *src, unsigned char* res, int len)
{
	snappy::Uncompress(src, input.size(), res);
}
 
struct thread_data {
	unsigned char* str;
	unsigned short* res;
	int length;
	int niter, tid;
};

void generate_data(unsigned char* buffer, int len) {
	for (int i = 0; i < len; i++)
		buffer[i] = rand() % 26 + 'a';
}

void thread_worker(void* inp_data) {
	unsigned char* str = ((struct thread_data*)inp_data)->str;
	unsigned short* res = ((struct thread_data*)inp_data)->res;
	int len = ((struct thread_data*)inp_data)->length;
	int niter = ((struct thread_data*)inp_data)->niter;
	int tid = ((struct thread_data*)inp_data)->tid;
	for (int i = 0; i < niter; i++) {
		int cLen = compress(str, res, len);
		decompress(res, str, cLen);
	}
}

int main(int argc, char** argv)
{
	thread threads[MAX_THREAD];
	int num_thread;
	int niters, len;
	if (argc == 1) {
		len = 1500, num_thread = 1;
		niters = 100;
	}
	else if (argc == 2) {
		len = atoi(argv[1]);
		niters = 100, num_thread = 1;
	}
	else if (argc == 3) {
		len = atoi(argv[1]);
		niters = atoi(argv[2]);
		num_thread = 1;
	}
	else {
		len = atoi(argv[1]);
		niters = atoi(argv[2]);
		num_thread = atoi(argv[3]);
	}

	for (int i = 0; i < num_thread; i++)
		generate_data(&inp[i * len], len);

	struct thread_data* thread_inp = (struct thread_data*)malloc(sizeof(struct thread_data) * num_thread);

	// initialize per thread data
	for (int i = 0; i < num_thread; i++) {
		thread_inp[i].length = len;
		thread_inp[i].niter = niters;
		thread_inp[i].str = &inp[i * len];
		thread_inp[i].res = &outp[len * i];
		thread_inp[i].tid = i;
	}

	struct timeval start, end;

	gettimeofday(&start, NULL);

	for (int i = 0; i < num_thread; i++) {
		threads[i] = thread(thread_worker, (void*)&thread_inp[i]);
	}

	// thread_worker((void *)&thread_inp[0]);

	int* ret = NULL;

	for (int i = 0; i < num_thread; i++)
		threads[i].join();

	gettimeofday(&end, NULL);

	double time_taken = double(1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)) / double(1e6);

	printf("spend %fs\n", time_taken);
	printf("Snappy : %lld MB per second\n", (long long)((float)(niters * num_thread * len) / (float)(time_spend * 1024 * 1024)));

	free(thread_inp);

	return 0;
}