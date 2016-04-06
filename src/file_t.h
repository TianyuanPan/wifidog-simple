/*
 * file_t.h
 *
 *  Created on: Apr 6, 2016
 *      Author: TianyuanPan
 */

#ifndef FILE_T_H_
#define FILE_T_H_

#define  PREFIX "/tmp/.dogexcuteresultdir/"

typedef  struct {
	char name[1024];
	FILE *fp;
}FILE_T;


FILE_T * excute_open(const char *command, const char *mode);


size_t excute_read(void *ptr, size_t size, size_t nmemb, FILE_T *stream);


size_t excute_write(void *ptr, size_t size, size_t nmemb, FILE_T *stream);


int excute_close(FILE_T *pft);



int init_excute_outdir();

#endif /* FILE_T_H_ */
