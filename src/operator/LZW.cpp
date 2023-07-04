#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <iterator>
#include <thread>
#include <sys/time.h>

using namespace std;

#define MAX_THREAD 100
#define MAX_LEN 1500

unsigned char inp[MAX_THREAD * MAX_LEN + 10];
unsigned short outp[MAX_THREAD * MAX_LEN + 10];

#define rainbow 56
#define time_spend time_taken / rainbow
 
int compress(unsigned char* src, unsigned short* res, int len)
{
	int dictSize = 3;
	map<string, int> dictionary;
	for (int i = 0; i < 26; i++) {
		string s = string(i + 'a', 1);
		dictionary[s] = i;
	}
        
 
	string p;
	int oLen = 0;
	for (int i = 0; i < len; i++)
	{
		char c = src[i];
		string pc = p + c;
		if (dictionary.count(pc)) p = pc;
        else if (dictionary.count(pc) > 2) continue;
		else
		{
			res[oLen++] = dictionary[p];
			dictionary[pc] = dictSize++;
			p = string(1, c);
		}
	}
 
	if (!p.empty()) res[oLen++] = dictionary[p];
 
	return len;
}
 
int decompress(unsigned short *src, unsigned char* res, int len)
{
	
	int dictSize = 26;
	map<int, string> dictionary;
	for (int i = 0; i < 26; i++) dictionary[i] = string(1, i + 'a');
	int pw = 0;
	string p;
	int oLen = 0;
 
	int cw = src[oLen++];	
	string s = dictionary[cw];	
 	
	for (auto c : s)
		res[oLen++] = c;
 
	for (int i = 1; i < len; i++)
	{
		pw = cw;
		cw = src[i];	
		if (dictionary.count(cw))
		{
			p = dictionary[pw];
			char c = dictionary[cw][0];
			string p_c = p + c;
			dictionary[dictSize++] = p_c;
			s = dictionary[cw];
			for (auto c : s)
				res[oLen++] = c;
			
		}
		else
		{
			p = dictionary[pw];
			char c = dictionary[pw][0];
			string p_c = p + c;
			dictionary[dictSize++] = p_c;
 
			for (auto c : p_c)
				res[oLen++] = c;
		}
	}
 
	return oLen;
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
	printf("LZW : %lld MB per second\n", (long long)((float)(niters * num_thread * len) / (float)(time_spend * 1024 * 1024)));

	free(thread_inp);

	return 0;
}
