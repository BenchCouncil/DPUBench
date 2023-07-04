#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <thread>

using namespace std;

#define MAX_LEN 1500
#define MAX_THREAD 100

unsigned char inp[MAX_THREAD * MAX_LEN + 10];
unsigned char outp[MAX_THREAD * MAX_LEN + 10];
char thread_buffer[MAX_THREAD * MAX_LEN * 4 + 10];

int getNi(int e, int n)
{
	int d;
	for (d = 0; d < n; d++) {
		if (e * d % n == 1)
			return d;
	}
    return 0;
}

int Gcd(int a, int b) 
{
	if (a % b == 0)
		return b;
	else;
	return Gcd(b, a % b);
}

int getrand(int p,int q) {
	int m=(p-1)*(q-1);
	int e,c;
	while (1 ) {
		srand((unsigned)time(NULL));
		e = rand() % m;
		c = Gcd(e, m);
		if (c == 1)
			break;
	}
	return e;
}
	
int powmod(int n, int d, int mod) {
    int res = 1;
    while (d) {
        if (d & 1) res = (long long)res * n % mod;
        n = (long long) n * n % mod;
        d >>= 1; 
    }
    return res;
}

void Encode(unsigned char *inp, int e, int n, int len, unsigned char* outp) {
	int flag = 1;
	for (int i = 0; i < len; i++) {
		outp[i] = powmod((int)inp[i], e, n);
		flag = 1;
	}
}

void Decode(unsigned char *inp, int d, int n, int length, unsigned char* outp) {
	int flag = 1;
	for (int i = 0; i < length; i++) {
		outp[i] = powmod((int)inp[i], d, n);
		flag = 1;
	}
}

struct thread_data{
    unsigned char* str;
    int length;
	int e, n, d;
    int niter;
    int tid;
};

void thread_worker(void* inp_data) {
    unsigned char* str = ((struct thread_data *) inp_data)->str;
    int len = ((struct thread_data *) inp_data)->length;
    int niter = ((struct thread_data *) inp_data)->niter;
	int e = ((struct thread_data *) inp_data)->e;
	int d = ((struct thread_data *) inp_data)->d;
	int n = ((struct thread_data *) inp_data)->n;
    int tid = ((struct thread_data *) inp_data)->tid;
    for (int i = 0; i < niter; i++) {
        Encode(str, e, n, len, &outp[len * tid]);
	    Decode(&outp[len * tid], d, n, len, str);
    }
}

void generate_data(unsigned char* buffer, int len) {
    for (int i = 0; i < len; i++)
        buffer[i] = rand() % 255;
}

int main(int argc, char** argv){
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

    int p = 13, q = 5;
    int n = p * q;
    int t = (q - 1) * (p - 1); 
    int e = getrand(p, q);
    int d = getNi(e, n);
    
    printf("key generation finish :\n");

    // initialize per thread data
    for (int i = 0; i < num_thread; i++) {
        thread_inp[i].length = len;
        thread_inp[i].niter = niters;
        thread_inp[i].str = &inp[i * len];
        thread_inp[i].tid = i;
        thread_inp[i].e = e;
        thread_inp[i].d = d;
        thread_inp[i].n = n;
    }

    struct timeval start, end;

    gettimeofday(&start, NULL);

    for (int i = 0; i < num_thread; i++) {
        threads[i] = thread(thread_worker, (void *)&thread_inp[i]);
    }

    // thread_worker((void *)&thread_inp[0]);

    int* ret = NULL;

    for (int i = 0; i < num_thread; i++)
        threads[i].join();

    gettimeofday(&end, NULL);

    double time_taken = double(1000000*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)) / double(1e6);
    
    printf("spend %fs\n", time_taken);
    printf("RSA : %lld MB per second\n", (long long)((float)(niters * num_thread * len) / (float)(time_taken * 1024 * 1024)));

    free(thread_inp);

    return 0;
}

