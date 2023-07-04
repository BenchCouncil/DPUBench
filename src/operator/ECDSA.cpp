#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <thread>

using namespace std;

#define MAXLEN 1024 * 1024
#define NUM_THREADS 100

#define ENCRPY(x) ((x * x + 2 * x + 2123 + x) * x) * x  

unsigned char res[MAXLEN];

#define MAX_THREAD 100
#define MAX_LEN 1500
#define SHA256_ROTL(a,b) (((a>>(32-b))&(0x7fffffff>>(31-b)))|(a<<b))
#define SHA256_SR(a,b) ((a>>b)&(0x7fffffff>>(b-1)))
#define SHA256_Ch(x,y,z) ((x&y)^((~x)&z))
#define SHA256_Maj(x,y,z) ((x&y)^(x&z)^(y&z))
#define SHA256_E0(x) (SHA256_ROTL(x,30)^SHA256_ROTL(x,19)^SHA256_ROTL(x,10))
#define SHA256_E1(x) (SHA256_ROTL(x,26)^SHA256_ROTL(x,21)^SHA256_ROTL(x,7))
#define SHA256_O0(x) (SHA256_ROTL(x,25)^SHA256_ROTL(x,14)^SHA256_SR(x,3))
#define SHA256_O1(x) (SHA256_ROTL(x,15)^SHA256_ROTL(x,13)^SHA256_SR(x,10))

void generate_data(unsigned char* buffer, int len) {
    for (int i = 0; i < len; i++)
        buffer[i] = rand() % 255;
}

unsigned char inp[MAX_THREAD * MAX_LEN + 10];
char thread_buffer[MAX_THREAD * MAX_LEN * 4 + 10];

int getNi(int e, int n)
{
	int d;
	for (d = 0; d < n; d++) {
		if (e * d % n == 1)
			return d;
	}
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
	

int getEclipsCoe(int e) {
    return Gcd(e, ENCRPY(e) + e * e);
}

struct thread_data{
    unsigned char* str;
    int length;
    unsigned char *res;
	int e, n, d;
    int niter, tid;
};

long K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void StrSHA256(unsigned char* str, int length, int tid) {
    char* ppend;
    char* pp = &thread_buffer[length * tid];
    long l, i, W[64], T1, T2, A, B, C, D, E, F, G, H, H0, H1, H2, H3, H4, H5, H6, H7;
    H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
    H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;
    l = length + ((length % 64 > 56) ? (128 - length % 64) : (64 - length % 64));
    for (i = 0; i < length; pp[i + 3 - 2 * (i % 4)] = str[i], i++);
    for (pp[i + 3 - 2 * (i % 4)] = 128, i++; i < l; pp[i + 3 - 2 * (i % 4)] = 0, i++);
    *((long*)(pp + l - 4)) = length << 3;
    *((long*)(pp + l - 8)) = length >> 29;

    for (ppend = pp + l; pp < ppend; pp += 64) {
        for (i = 0; i < 16; W[i] = ((long*)pp)[i], i++);
        for (i = 16; i < 64; W[i] = (SHA256_O1(W[i - 2]) + W[i - 7] + SHA256_O0(W[i - 15]) + W[i - 16]), i++);
        A = H0, B = H1, C = H2, D = H3, E = H4, F = H5, G = H6, H = H7;
        for (i = 0; i < 64; i++) {
            T1 = H + SHA256_E1(E) + SHA256_Ch(E, F, G) + K[i] + W[i];
            T2 = SHA256_E0(A) + SHA256_Maj(A, B, C);
            H = G, G = F, F = E, E = D + T1, D = C, C = B, B = A, A = T1 + T2;
        }
        H0 += A, H1 += B, H2 += C, H3 += D, H4 += E, H5 += F, H6 += G, H7 += H;
    }
}

void Encode(unsigned char *text, int e,int n) {
    e = getEclipsCoe(e);
	int flag = 1;
	for (int i = 0; i < strlen((char*)text); i++) {
		for (int j = 0; j < e; j++) {
			flag = flag * (int)text[i] % n;
		}
		res[i] = flag;
		flag = 1;
	}
    StrSHA256(text, strlen((char*)text), 0);
    
}

void Decode(unsigned char *text, int d, int n, int length) {
    d = getEclipsCoe(d);
    n = getEclipsCoe(n);
	int flag = 1;
	for (int i = 0; i < length; i++) {
		for (int j = 0; j < d; j++) {
			flag = flag * res[i] % n;
		}
		text[i] = flag;
		flag = 1;
	}
}

void thread_worker(void* inp_data) {
    unsigned char* str = ((struct thread_data *) inp_data)->str;
    int len = ((struct thread_data *) inp_data)->length;
    int niter = ((struct thread_data *) inp_data)->niter;
	int e = ((struct thread_data *) inp_data)->e;
	int d = ((struct thread_data *) inp_data)->d;
	int n = ((struct thread_data *) inp_data)->n;
    for (int i = 0; i < niter; i++) {
        Encode(str, e, n);
		Decode(str, d, n, strlen((char *)str));
    }
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
        threads[i] = thread(thread_worker, (void*)&thread_inp[i]);
    }

    // thread_worker((void *)&thread_inp[0]);

    int* ret = NULL;

    for (int i = 0; i < num_thread; i++)
        threads[i].join();

    gettimeofday(&end, NULL);

    double time_taken = double(1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)) / double(1e6);

    printf("spend %fs\n", time_taken);
    printf("RSA : %lld MB per second\n", (long long)((float)(niters * num_thread * len) / (float)(time_taken * 1024 * 1024)));

    free(thread_inp);

    return 0;
}
