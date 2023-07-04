#include <regex>
#include <iostream>
#include <fstream>
#include <string>
#include <sys/time.h>
#include <thread>
#include <vector>

using namespace std;

#define NUM_THREADS 20

#define MAX_THREAD 100
#define MAX_LEN 1500

char inp[100][100], out[100][100]; 
vector<string> istr, ostr;

struct thread_data{
    vector<string> *rule;
    vector<string> *data;
};

void thread_worker(void* inp_data) {
    vector<string> &rule  = *(((struct thread_data *) inp_data)->rule);
    vector<string> &data  = *(((struct thread_data *) inp_data)->data);
	double num = double(rand() % 19997928) / 19997928.0;
    
	int val = num * 30.0 + 100.0;

    for (auto str : data) {
		for (auto r : rule) 
		    for (int i = 0; i < val; i++)
		        regex_match(str, regex(r));
	}
}

int main(int argc, char** argv)
{
    thread threads[MAX_THREAD];
	int num_thread;
    if (argc == 1) {
        num_thread = 1;
	}
	else num_thread = atoi(argv[1]);
    
    ifstream rules("./regex_rule/regex_rules.txt");
    int i = 0;
	while (1) {
        rules.getline(inp[i], 100);
		if (inp[i][0] == '$') break;
		int p = 0;
		string str;
		while (inp[i][p] != '$') {
			str += inp[i][p]; 
			p++;
		}
		istr.push_back(str);
		i++;
	}
    
	i = 0;
	ifstream data("./regex_rule/data_to_scan.txt");
	while (1) {
        data.getline(out[i], 100);
		if (out[i][0] == '$') break;
		int p = 0;
		string str;
		while (out[i][p] != '$') {
			str += out[i][p];
			p++;
		}
		ostr.push_back(str);
		i++;
	}
    
    struct thread_data thread_inp;

    thread_inp.rule = &ostr;
	thread_inp.data = &istr;
    
	struct timeval start, end;

    gettimeofday(&start, NULL);

    for (int i = 0; i < num_thread; i++) {
        threads[i] = thread(thread_worker, (void *)&thread_inp);
    }

    // thread_worker((void *)&thread_inp[0]);

    int* ret = NULL;

    for (int i = 0; i < num_thread; i++)
        threads[i].join();

    gettimeofday(&end, NULL);

    double time_taken = double(1000000*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)) / double(1e6);
    
    printf("spend %fs\n", time_taken);
    printf("RXPMatch : %lld MB per second\n", (long long)((float)num_thread * 1600 * 110 / (float)(time_taken * 1024 * 1024)));
    
	return 0;
}