/*
 * file_t.c
 *
 *  Created on: Apr 6, 2016
 *      Author: TianyuanPan
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <syslog.h>

#include "util.h"
#include "debug.h"

#include "file_t.h"


static void init_file_t(FILE_T *pft)
{
	memset((void *)pft->name, 0, 1024);
	pft->fp = NULL;
}


FILE_T * excute_open(const char *command, const char *mode)
{
	FILE_T *pft = NULL;
	char cmd_line[4096];
	unsigned int rand_n;

	rand_n = rand()%(9999 - 1000 + 1) + 1000;

	pft = (FILE_T *)safe_malloc(sizeof(FILE_T));

	if (!pft)
		return NULL;

	init_file_t(pft);


	sprintf(pft->name, "%sdocmdout_%u", PREFIX, rand_n);

	/* FIX ME? */
     char *pp = NULL;
     pp = strstr(command, "\n");//
     if(pp)
       *pp = 0;//

	sprintf(cmd_line, "%s > %s", command, pft->name);

	debug(LOG_INFO, "remote command line: %s", cmd_line);

	if (execute(cmd_line, 1) != 0){
		remove(pft->name);
		free(pft);
		return NULL;
	}

	pft->fp = fopen(pft->name, mode);

	if (!pft->fp){
		remove(pft->name);
		free(pft);
		return NULL;
	}
	return pft;
}

size_t excute_read(void *ptr, size_t size, size_t nmemb, FILE_T *stream)
{
	return fread(ptr, size, nmemb, stream->fp);
}


size_t excute_write(void *ptr, size_t size, size_t nmemb, FILE_T *stream)
{
	return fwrite(ptr, size, nmemb, stream->fp);
}


int excute_close(FILE_T *pft)
{
	fclose(pft->fp);

	if (remove(pft->name) != 0){
		free(pft);
		return -1;
	}

	free(pft);

	return 0;
}


int init_excute_outdir()
{
	char cmd_line[128];
	sprintf(cmd_line,"rm -rf %s;mkdir %s", PREFIX, PREFIX);
	if (execute(cmd_line, 1) != 0){
		return -1;
	}
	return 0;
}

