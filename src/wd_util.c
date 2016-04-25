/* vim: set et sw=4 sts=4 ts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/**
  @file wd_util.c
  @brief Misc utility functions
  @author Copyright (C) 2015 Alexandre Carmel-Veilleux <acv@miniguru.ca>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include "common.h"
#include "gateway.h"
#include "commandline.h"
#include "client_list.h"
#include "conf.h"
#include "safe.h"
#include "util.h"
#include "wd_util.h"
#include "debug.h"
#include "pstring.h"

#include "../config.h"


long served_this_session = 0;


/*
 * @return A string containing human-readable status text. MUST BE free()d by caller
 */
char *
get_status_text()
{
    pstr_t *pstr = pstr_new();
    s_config *config;
    t_client *sublist, *current;
    int count;
    time_t uptime = 0;
    unsigned int days = 0, hours = 0, minutes = 0, seconds = 0;

    uptime = time(NULL) - started_time;
    days = (unsigned int)uptime / (24 * 60 * 60);
    uptime -= days * (24 * 60 * 60);
    hours = (unsigned int)uptime / (60 * 60);
    uptime -= hours * (60 * 60);
    minutes = (unsigned int)uptime / 60;
    uptime -= minutes * 60;
    seconds = (unsigned int)uptime;

    pstr_cat(pstr, "{");
    pstr_cat(pstr, "\"version\":\"" VERSION "\",");
    pstr_append_sprintf(pstr, "\"uptime\":\"%ud %uh %um %us\",", days, hours, minutes, seconds);
    pstr_append_sprintf(pstr, "\"clients_served_session\":\"%lu\",", served_this_session);

    LOCK_CLIENT_LIST();

    count = client_list_dup(&sublist);

    UNLOCK_CLIENT_LIST();

    current = sublist;

    count = 0;
    pstr_cat(pstr, "\"clients\":[");
    while (current != NULL) {
        pstr_append_sprintf(pstr, "\"%s\"", current->mac);
        count++;
        current = current->next;
        if (current != NULL)
        	pstr_cat(pstr, ",");
    }
    pstr_cat(pstr, "],");

    pstr_append_sprintf(pstr, "\"client_counter\":%d,", count);

    client_list_destroy(sublist);

    config = config_get_config();

    pstr_cat(pstr, "\"authentication_server\":{");

    LOCK_CONFIG();

    if (config->auth_servers != NULL)
        pstr_append_sprintf(pstr, "\"host\":\"%s\",\"ip\":\"%s\"}}",
        		             config->auth_servers->authserv_hostname,
        		             config->auth_servers->last_ip
        		            );
    else
    	pstr_cat(pstr, "}}");

    UNLOCK_CONFIG();

    return pstr_to_string(pstr);
}



