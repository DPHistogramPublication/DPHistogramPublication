#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <iostream>
#include <fstream>
#include <random>
#include "mt19937ar2.h"
#include "MemoryOperation.h"

using namespace std;

//** [PATH] **//
// location file (input)
#define LOC_FILE "../data/Foursquare_TIST15_MH/all_records.csv"
// census file (input)
#define CEN_FILE "../data/USCensus1990/all_records.csv"
// prefix of result file (output)
#define RES_FILE "../results/Res_RR"

//** [PARAMETER] **//
// #runs
#define RUN_NUM 100
// normalize counts to probabilities (1:yes, 0:no)
//#define NORMALIZE 1
#define NORMALIZE 0

// #vertical regions
#define V_NUM 25
// #horizontal regions
#define H_NUM 25
// minimum of latitude
#define V_MIN 40.7
// maximum of latitude
#define V_MAX 40.8
// minimum of longitude
#define H_MIN -74.04
// maximum of longitude
#define H_MAX -73.92

#define MAX_CHAR_NUM		100000

// #categories
int CatNum;
// maximum #events
int MaxEventNum;

// matrix Q
double **Q;

// event
int *Event;
// noisy event
int *NEvent;
// #users
int UserNum;
// event distribution
double *EventDist;
// noisy event distribution
double *NEventDist;
// estimated event distribution
double *EstEventDist;

FILE *FileOpen(string filename, const char *mode) {
	FILE *fp;

	if ((fp = fopen(filename.c_str(), mode)) == NULL) {
		cout << "cannot open " << filename << endl;
		exit(-1);
	}
	return fp;
}

// Read location file
void ReadLocFile(){
	double bou_v[V_NUM], bou_h[H_NUM];
	double v, h;
	int v_no, h_no, r_no;
	char *poi;
	char s[MAX_CHAR_NUM];
	FILE *fp;
	char *tok;
	int i, j;

	UserNum = 0;

	// calculate the boundary of regions --> bou_v, bou_h
	for (i = 0; i < V_NUM; i++){
		bou_v[i] = V_MIN + (V_MAX - V_MIN) * (double)i / (double)V_NUM;
	}
	for (i = 0; i < H_NUM; i++){
		bou_h[i] = H_MIN + (H_MAX - H_MIN) * (double)i / (double)H_NUM;
	}
//	for(i=0;i<V_NUM;i++) cout << bou_v[i] << endl;
//	for(i=0;i<H_NUM;i++) cout << bou_h[i] << endl;

	fp = FileOpen(LOC_FILE, "r");

	// read location file
	i = 0;
	while (fgets(s, MAX_CHAR_NUM, fp) != NULL){
		i++;

		// longitude --> h
		if ((tok = strtok(s, ",")) == NULL){
			printf("Error: File format is incorrect.\n");
			exit(-1);
		}
		for (j = 0; j < 2; j++){
			if ((tok = strtok(NULL, ",")) == NULL){
				printf("Error: File format is incorrect.\n");
				exit(-1);
			}
		}
		h = atof(tok);

		// latitude --> v
		if ((tok = strtok(NULL, ",")) == NULL){
			printf("Error: File format is incorrect.\n");
			exit(-1);
		}
		v = atof(tok);

		// latitude ID --> h_no
		if (h < H_MIN || h > H_MAX){
			printf("Warning: There is a location out of range (line:%d, longitude:%f, latitude:%f). We skip this location.\n", i, h, v);
			continue;
		}
		for (j = 0; j < H_NUM - 1; j++){
			if (h >= bou_h[j] && h < bou_h[j + 1]) break;
		}
		h_no = j;

		// longitude ID --> v_no
		if (v < V_MIN || v > V_MAX){
			printf("Warning: There is a location out of range (line:%d, longitude:%f, latitude:%f). We skip this location.\n", i, h, v);
			continue;
		}
		for (j = 0; j < V_NUM - 1; j++){
			if (v >= bou_v[j] && v < bou_v[j + 1]) break;
		}
		v_no = j;

		// region ID --> r_no
		r_no = v_no * H_NUM + h_no;
//		cout << h << " " << v << " " << h_no << " " << v_no << " " << r_no << endl;

		if (UserNum == MaxEventNum){
			printf("Error: The total number of events exceeds the maximum limit (=%d).\n", MaxEventNum);
			exit(-1);
		}

		// original region ID --> Event[UserNum]
		Event[UserNum] = v_no * H_NUM + h_no;
		UserNum++;
	}

	fclose(fp);

	printf("Total number of events: %d\n", UserNum);
}

// Read census file
void ReadCenFile() {
	char s[MAX_CHAR_NUM];
	FILE *fp;
	char *tok;
	int user_num;
	int i;

	UserNum = 0;

	fp = FileOpen(CEN_FILE, "r");

	// read category file
	while (fgets(s, MAX_CHAR_NUM, fp) != NULL) {
		if ((tok = strtok(s, ",")) == NULL) {
			printf("Error: File format is incorrect.\n");
			exit(-1);
		}

		if ((tok = strtok(NULL, ",")) == NULL) {
			printf("Error: File format is incorrect.\n");
			exit(-1);
		}

		// original category ID --> Event[UserNum]
		Event[UserNum] = atoi(tok);
		UserNum++;
	}

	fclose(fp);

	printf("Total number of events: %d\n", UserNum);
}

// Calculate local epsilon using the bound for k-RR [Feldman+, FOCS21] (Corrolary IV.2)
double CalcEpsL_RR(int n, int k, double eps){
	double delta = 0.00000001;	// 10^{-8}
	double epsl_max;
	double epsl_min = 0.01;
	double epsl_shift = 0.01;
	double epsl, eps_now;
	double term1, term2;

	if (eps == -1.0) return eps;

	epsl_max = log((double)n / (16.0 * log(2.0 / delta)));
//	cout << epsl_max << endl;

	for (epsl = epsl_max; epsl >= epsl_min; epsl -= epsl_shift){
		term1 = 4.0 * sqrt(2.0 * ((double)k + 1.0) * log(4.0 / delta)) / sqrt((exp(epsl) + k - 1) * (double)k * (double)n);
		term2 = 4.0 * ((double)k + 1.0) / ((double)k * (double)n);
		eps_now = log(1.0 + (exp(epsl) - 1.0) * (term1 + term2));
		if(eps_now <= eps) break;
	}

	epsl = max(epsl, eps);

	return epsl;
}

// Calculate (absolute frequency) distribution from events
void CalcDist(int *ev, int ev_num, double *dist){
	int i;

	// initialization
	for (i = 0; i < CatNum; i++) dist[i] = 0.0;

	// increase the population by one for each event
	for (i = 0; i < ev_num; i++) dist[ev[i]] += 1.0;

	// normalize counts to probabilities
	if(NORMALIZE){
		for (i = 0; i < CatNum; i++) dist[i] /= (double)ev_num;
	}
}

// Calculate matrix Q
void CalcQ(double **mat, int cat_num, int obf_mechanism, double epsilon) {
	double p1, p2;
	int i, j;

	// obfuscation mechanism
	switch (obf_mechanism) {
	// RR
	case 1:
		for (i = 0; i < cat_num; i++) {
			for (j = 0; j < cat_num; j++) {
				if (epsilon != -1.0){
					if (i == j) mat[i][j] = exp(epsilon) / (exp(epsilon) + (double)cat_num - 1.0);
					else mat[i][j] = 1.0 / (exp(epsilon) + (double)cat_num - 1.0);
				}
				else{
					if (i == j) mat[i][j] = 1.0;
					else mat[i][j] = 0.0;
				}
			}
		}
		break;
	// others
	default:
		printf("Incorrect [OBF_MECHANISM] (=%d)\n);", obf_mechanism);
		exit(-1);
	}
}

// Add noise to events
void AddNoise(int *ev, int *nev, double **mat, int ev_num, int cat_num){
	int ev_now;
	double rnd;
	double prob_sum;
	int i, j;

	// for each user
	for (i = 0; i < ev_num; i++) {
		// current event --> ev_now
		ev_now = ev[i];

		// generate random value --> rnd
		rnd = genrand_real1();

		// determine noisy event --> nev[i]
		prob_sum = 0.0;
		// for each category
		for (j = 0; j < cat_num; j++) {
			prob_sum += mat[ev_now][j];
			if (prob_sum >= rnd) break;
		}
		if (j == cat_num) {
			j = cat_num - 1;
			printf("Warning: Random number (=%f) exceeds the sum of probabilities over regions (=%f). We select the last category ID (=%d)\n", rnd, prob_sum, j);
		}
		nev[i] = j;
	}
}

// Distribution estimation by empirical estimation
// (decoder: w/o normalization (0), w/ significance threshold (1))
void EmpiricalEstimation(double *nev_dist, int obf_mechanism, double *est_dist, int cat_num, double eps, int decoder, int ev_num){
	double est_dist_sum;
	int i, j;
	double phi_inv, sd, thr;
	double zero_cat_num = 0;

	// initialization of estimated distribution
	for (i = 0; i < cat_num; i++) est_dist[i] = 0.0;

	// obfuscation mechanism
	switch (obf_mechanism){
	// RR
	case 1:
		for (i = 0; i < cat_num; i++){
			if (eps != -1.0){
				// absolute frequency
				est_dist[i] = ((double)cat_num - 1.0 + exp(eps)) / (exp(eps) - 1.0) * nev_dist[i] - (double)ev_num / (exp(eps) - 1.0);
				// relative frequency
//				est_dist[i] = ((double)cat_num - 1.0 + exp(eps)) / (exp(eps) - 1.0) * nev_dist[i] - 1.0 / (exp(eps) - 1.0);
			}
			else{
				est_dist[i] = nev_dist[i];
			}
		}
		break;
	// others
	default:
		printf("Incorrect [OBF_MECHANISM] (=%d)\n);", obf_mechanism);
		exit(-1);
	}

	// w/ significance threshold
	if (decoder == 1){
		// Phi inverse (Phi^{-1}(1 - 0.05 / cat_num) calculated from NORM.INV of excel) --> phi_inv
		if (cat_num == 400) phi_inv = 3.66226;
		else if (cat_num == 625) phi_inv = 3.775012;
		else{
			printf("cannot calculate phi_inv (cat_num = %d).\n", cat_num);
			exit(-1);
		}

		// obfuscation mechanism
		switch (obf_mechanism){
		// RR
		case 1:
			// standard deviation --> sd
			// absolute frequency
			// var = ((cat_num + exp(eps) - 2) * ev_num) /(exp(eps) - 1)^2
			if (eps != -1.0) sd = sqrt(((double)cat_num + exp(eps) - 2.0) * (double)ev_num) / (exp(eps) - 1.0);
			// relative frequency
			// var = ((cat_num + exp(eps) - 2) / ev_num) /(exp(eps) - 1)^2
//			if (eps != -1.0) sd = sqrt(((double)cat_num + exp(eps) - 2.0) / (double)ev_num) / (exp(eps) - 1.0);
			else sd = 0.0;
			// threshold for non-zeros --> thr
			thr = phi_inv * sd;
//			cout << phi_inv << " " << sd << " " << thr << endl;
			break;
		// others
		default:
			printf("Incorrect [OBF_MECHANISM] (=%d)\n);", obf_mechanism);
			exit(-1);
		}

		for (i = 0; i < cat_num; i++){
			if (est_dist[i] <= thr){
				est_dist[i] = 0.0;
				zero_cat_num++;
			}
		}

		// sum of estimated distribution --> est_dist_sum
		est_dist_sum = 0.0;
		for (i = 0; i < cat_num; i++) est_dist_sum += est_dist[i];

		// assign uniform distribution for zeros
		for (i = 0; i < cat_num; i++){
			// absolute frequency
			if (est_dist_sum <= (double)ev_num && est_dist[i] == 0) est_dist[i] = ((double)ev_num - est_dist_sum) / zero_cat_num;
			// relative frequency
//			if (est_dist_sum <= 1.0 && est_dist[i] == 0) est_dist[i] = (1.0 - est_dist_sum) / zero_cat_num;
		}
	}
}

// Calculate MAE between two distributions
double MAE(double *dist1, double *dist2){
	double mae = 0.0;
	double l1_loss;
	int i;

	for (i = 0; i < CatNum; i++){
		l1_loss = fabs(dist1[i] - dist2[i]);
		mae += l1_loss;
	}
	mae /= (double)CatNum;

	return mae;
}

// Calculate MSE between two distributions
double MSE(double *dist1, double *dist2){
	double mse = 0.0;
	double l2_loss;
	int i;

	for (i = 0; i < CatNum; i++){
		l2_loss = (dist1[i] - dist2[i]) * (dist1[i] - dist2[i]);
		mse += l2_loss;
	}
	mse /= (double)CatNum;

	return mse;
}

int main(int argc, char *argv[])
{
	// distribution estimation method
	// (0:Empirical Estimation (w/o normalization), 1::Empirical Estimation (w/ significance threshold))
	int est_method_num = 2;
	int est_method[est_method_num] = {0,1};
	// parameter epsilon (-1: do not add noise)
	int eps_num = 24;
	double eps[eps_num] = {0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1,1.2,1.4,1.6,1.8,2,3,4,5,6,7,8,9,10,-1};
	double epsl;

	int data_type;
	int obf_mechanism;
	int privacy_model;
	char resfile[1025];
	int ep, em, rn;
	double mae_est_avg[est_method_num];
	double mse_est_avg[est_method_num];
	double mae_est_std[est_method_num];
	double mse_est_std[est_method_num];
	double est_dist_sum;
	double mae_est, mse_est;
	FILE *fp;
	double dtmp;
	int i, j;

	// Initialization of Mersennne Twister
	unsigned long init[4] = { 0x123, 0x234, 0x345, 0x456 }, length = 4;
	init_by_array(init, length);
//	init_genrand(1);

	if (argc < 4) {
	    printf("Usage: %s [DATA_TYPE] [OBF_MECHANISM] [PRIVACY_MODEL]\n\n", argv[0]);
		printf("[DATA_TYPE]: Data type (1: Foursquare_TIST15_MH, 2: USCensus1990)\n");
		printf("[OBF_MECHANISM]: Obfuscation mechanism (1: RR)\n");
		printf("[PRIVACY_MODEL]: Privacy model (1: local, 2: shuffle)\n");
		return -1;
	}

	data_type = atoi(argv[1]);
	obf_mechanism = atoi(argv[2]);
	privacy_model = atoi(argv[3]);

	// Set CatNum and MaxEventNum
	switch(data_type){
		// Foursquare_TIST15_MH
		case 1:
			CatNum = V_NUM * H_NUM;
			MaxEventNum = 359054;
			break;
		// USCensus1990
		case 2:
			CatNum = 400;
			MaxEventNum = 2458285;
			break;
		default:
			printf("Incorrect [DATA_TYPE]\n");
			exit(-1);
	}

	// malloc
	malloc1D(&EventDist, CatNum);
	malloc1D(&NEventDist, CatNum);
	malloc1D(&EstEventDist, CatNum);
	malloc1D(&Event, MaxEventNum);
	malloc1D(&NEvent, MaxEventNum);
	malloc2D(&Q, CatNum, CatNum);

	// read input file --> Event, UserNum
	switch(data_type){
		// Foursquare_TIST15_MH
		case 1:
			ReadLocFile();
			break;
		// USCensus1990
		case 2:
			ReadCenFile();
			break;
	}
//	for(i=0;i<UserNum;i++) cout << i << " " << Event[i] << endl;

	// calculate true distribution from events --> EventDist
	CalcDist(Event, UserNum, EventDist);
//	for(i=0;i<CatNum;i++) cout << i << " " << EventDist[i] << endl;

	// output header to result file
	for (em = 0; em < est_method_num; em++){
		sprintf(resfile, "%s_dt%d_om%d_em%d_pm%d.csv", RES_FILE, data_type, obf_mechanism, est_method[em], privacy_model);
		fp = FileOpen(resfile, "w");
		fprintf(fp, "epsilon,MAE_avg,MSE_avg,MAE_std,MSE_std,epsilon(local)\n");
		fclose(fp);
	}

	// for each parameter epsilon
	for (ep = 0; ep < eps_num; ep++){
		// local epsilon --> epsl
		switch(privacy_model){
			// local model
			case 1:
				epsl = eps[ep];
				break;
			// shuffle model
			case 2:
				epsl = CalcEpsL_RR(UserNum, CatNum, eps[ep]);
				break;
			// others
			default:
				printf("Incorrect [PRIVACY_MODEL]\n");
				exit(-1);
		}
//		cout << eps[ep] << " " << epsl << endl;

		// initialization
		for (em = 0; em < est_method_num; em++) {
			mae_est_avg[em] = mse_est_avg[em] = 0.0;
			mae_est_std[em] = mse_est_std[em] = 0.0;
		}

		// for each run
		for (rn = 0; rn < RUN_NUM; rn++){
			// calculate matrix Q --> Q
			CalcQ(Q, CatNum, obf_mechanism, epsl);
//			for(i=0;i<CatNum;i++){
//				for(j=0;j<CatNum;j++) cout << i << " " << j << " " << Q[i][j] << endl;
//			}

			// Add noise to events --> NEvent
			AddNoise(Event, NEvent, Q, UserNum, CatNum);
//			for(i=0;i<UserNum;i++) cout << i << " " << Event[i] << " " << NEvent[i] << endl;

			// calculate noisy event distribution --> NEventDist
			CalcDist(NEvent, UserNum, NEventDist);
//			for(i=0;i<CatNum;i++) cout << i << " " << EventDist[i] << " " << NEventDist[i] << endl;

			// for each distribution estimation method
			for (em = 0; em < est_method_num; em++) {

				// distribution estimation by empirical estimation --> EstEventDist
				EmpiricalEstimation(NEventDist, obf_mechanism, EstEventDist, CatNum, epsl, est_method[em], UserNum);

				// normalize so that the sum is 1
				if(NORMALIZE){
					est_dist_sum = 0.0;
					for (i = 0; i < CatNum; i++) est_dist_sum += EstEventDist[i];
					if (est_dist_sum != 0) {
						for (i = 0; i < CatNum; i++) EstEventDist[i] = EstEventDist[i] / est_dist_sum;
					}
					else {
						for (i = 0; i < CatNum; i++) EstEventDist[i] = 1.0 / (double)CatNum;
					}
				}

//				for(i=0;i<CatNum;i++) cout << i << " " << EventDist[i] << " " << NEventDist[i] << " " << EstEventDist[i] << endl;
//				est_dist_sum = 0.0;
//				for (i = 0; i < CatNum; i++) est_dist_sum += EstEventDist[i];
//				cout << est_dist_sum << endl;

				// MAE between true event distribution and estimated distribution --> mae_est
				mae_est = MAE(EventDist, EstEventDist);
				mae_est_avg[em] += mae_est;
				mae_est_std[em] += (mae_est * mae_est);

				// MSE between true event distribution and estimated distribution --> mse_est
				mse_est = MSE(EventDist, EstEventDist);
				mse_est_avg[em] += mse_est;
				mse_est_std[em] += (mse_est * mse_est);
			}
		}

		// calculate average MAE and MSE
		for (em = 0; em < est_method_num; em++){
			mae_est_avg[em] /= (double)RUN_NUM;
			mse_est_avg[em] /= (double)RUN_NUM;
		}

		// calculate standard deviation of MAE and MSE
		for (em = 0; em < est_method_num; em++){
			dtmp = mae_est_std[em] / (double)RUN_NUM - mae_est_avg[em] * mae_est_avg[em];
			if (dtmp <= 0.0) mae_est_std[em] = 0.0;
			else mae_est_std[em] = sqrt(dtmp);
			dtmp = mse_est_std[em] / (double)RUN_NUM - mse_est_avg[em] * mse_est_avg[em];
			if (dtmp <= 0.0) mse_est_std[em] = 0.0;
			else mse_est_std[em] = sqrt(dtmp);
		}

		// output results to result file
		for (em = 0; em < est_method_num; em++){
//			printf("EPSILON:%f, EST_METHOD:%d, MAE: %e, MSE: %e, EPSILON(local):%f\n", eps[ep], est_method[em], mae_est_avg[em], mse_est_avg[em], epsl);
			sprintf(resfile, "%s_dt%d_om%d_em%d_pm%d.csv", RES_FILE, data_type, obf_mechanism, est_method[em], privacy_model);
			fp = FileOpen(resfile, "a");
			fprintf(fp, "%f,%e,%e,%e,%e,%f\n", eps[ep], mae_est_avg[em], mse_est_avg[em], mae_est_std[em], mse_est_std[em], epsl);
			fclose(fp);
		}
	}

	// free
	free1D(EventDist);
	free1D(NEventDist);
	free1D(EstEventDist);
	free1D(Event);
	free1D(NEvent);
	free2D(Q, CatNum);

	return 0;
}

