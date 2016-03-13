/* vim: set et sw=4 ts=4 sts=4 : */
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

/* $Id$ */
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire
  @author Copyright (C) 2007 David Bird <david@coova.com>

 */
/* Note that libcs other than GLIBC also use this macro to enable vasprintf */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "httpd.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "firewall.h"
#include "http.h"
#include "client_list.h"
#include "common.h"
#include "util.h"
#include "wd_util.h"

#include "../config.h"


/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_404(httpd * webserver, request * r, int error_code)
{
    char tmp_url[MAX_BUF], *url, *mac;
    s_config *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();

    memset(tmp_url, 0, sizeof(tmp_url));
    /* 
     * XXX Note the code below assumes that the client's request is a plain
     * http request to a standard port. At any rate, this handler is called only
     * if the internet/auth server is down so it's not a huge loss, but still.
     */
    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
             r->request.host, r->request.path, r->request.query[0] ? "?" : "", r->request.query);
    url = httpdUrlEncode(tmp_url);

        /* Re-direct them to auth server */
        char *urlFragment;

        if (!(mac = arp_get(r->clientAddr))) {

            return;///
        } else {
            debug(LOG_INFO, "Got client MAC address for ip %s: %s", r->clientAddr, mac);
            safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&ip=%s&mac=%s&url=%s",
                          auth_server->authserv_login_script_path_fragment,
                          config->gw_address, config->gw_port, config->gw_id, r->clientAddr, mac, url);
            free(mac);
        }

        debug(LOG_INFO, "Captured %s requesting [%s] and re-directing them to login page", r->clientAddr, url);
        http_send_redirect_to_auth(r, urlFragment, "Redirect to login page");
        free(urlFragment);
    free(url);
}

void
http_callback_wifidog(httpd * webserver, request * r)
{
    send_http_page(r, "WiFiDog", "Please use the menu to navigate the features of this WiFiDog installation.");
}

void
http_callback_about(httpd * webserver, request * r)
{
    send_http_page(r, "About WiFiDog", "This is WiFiDog version <strong>" VERSION "</strong>");
}

void
http_callback_status(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    char *status = NULL;
    char *buf;

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Status page requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    status = get_status_text();
    safe_asprintf(&buf, "<pre>%s</pre>", status);
    send_http_page(r, "WiFiDog Status", buf);
    free(buf);
    free(status);
}

/** @brief Convenience function to redirect the web browser to the auth server
 * @param r The request
 * @param urlFragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title */
void
http_send_redirect_to_auth(request * r, const char *urlFragment, const char *text)
{
    char *protocol = NULL;
    int port = 80;
    t_auth_serv *auth_server = get_auth_server();

    if (auth_server->authserv_use_ssl) {
        protocol = "https";
        port = auth_server->authserv_ssl_port;
    } else {
        protocol = "http";
        port = auth_server->authserv_http_port;
    }

    char *url = NULL;
    safe_asprintf(&url, "%s://%s:%d%s%s",
                  protocol, auth_server->authserv_hostname, port, auth_server->authserv_path, urlFragment);
    http_send_redirect(r, url, text);
    free(url);
}

/** @brief Sends a redirect to the web browser 
 * @param r The request
 * @param url The url to redirect to
 * @param text The text to include in the redirect header and the manual redirect link title.  NULL is acceptable */
void
http_send_redirect(request * r, const char *url, const char *text)
{
    char *message = NULL;
    char *header = NULL;
    char *response = NULL;
    /* Re-direct them to auth server */
    debug(LOG_DEBUG, "Redirecting client browser to %s", url);
    safe_asprintf(&header, "Location: %s", url);
    safe_asprintf(&response, "302 %s\n", text ? text : "Redirecting");
    httpdSetResponse(r, response);
    httpdAddHeader(r, header);
    free(response);
    free(header);
    safe_asprintf(&message, "Please <a href='%s'>click here</a>.", url);
    send_http_page(r, text ? text : "Redirection to message", message);
    free(message);
}

static int allow_client(httpd * webserver, request * r)
{
	debug(LOG_DEBUG,"Function: allow_client");
    t_client *client, *tmp;
    s_config *config = NULL;
    char *mac;

    if (!(mac = arp_get(r->clientAddr))) {
        /* We could not get their MAC address */
        debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
        send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
        debug(LOG_ERR, "==== MAC UNDEFIND ====\n");
        return -1;
    }

        LOCK_CLIENT_LIST();

        if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
            debug(LOG_DEBUG, "New client for %s", r->clientAddr);
            client_list_add(r->clientAddr, mac);
        }else{
        	UNLOCK_CLIENT_LIST();
        	debug(LOG_INFO, "client for %s already in list.", r->clientAddr);
        	return 0;
        }

        tmp = client_list_find_by_ip(r->clientAddr);

        if (tmp == NULL){
        	UNLOCK_CLIENT_LIST();
        	debug(LOG_ERR, "Could not get client from client_list [ ip: %s ]", r->clientAddr);
        	return -1;
        }
        tmp->fw_connection_state = FW_MARK_KNOWN;

        client = client_dup(tmp);

        UNLOCK_CLIENT_LIST();

        if (client == NULL) {
            debug(LOG_ERR, "authenticate_client(): Could not dup client from tmp [ ip: %s mac: %s ]", tmp->ip, tmp->mac);
            return -1;
        }

        if (fw_allow(client, FW_MARK_KNOWN) != 0){
        	client_list_destroy(client);

        	LOCK_CLIENT_LIST();
        	client = client_list_find_by_ip(r->clientAddr);

        	if (client != NULL)
        		client_list_delete(client);

        	UNLOCK_CLIENT_LIST();

        	debug(LOG_ERR, "add client [%s, %s] to list error.", r->clientAddr, mac);

        	return -1;
        }

        served_this_session++;
        client_list_destroy(client);

        return 0;
}

void http_callback_release(httpd * webserver, request * r)
{
	debug(LOG_INFO,"Function: http_callback_release");

	if (allow_client(webserver, r) == 0)
        httpdOutput(r, "OK.");

    return;
}


void http_callback_allow_redirect(httpd * webserver, request * r)
{
	debug(LOG_INFO, "Function: http_callback_allow_redirect");
	char url[HTTP_MAX_URL],
	     *ptr = NULL,
	     *ops = NULL;
	int ret,
	    protocol;

	ret = allow_client(webserver, r);

	if ( ret != 0){
		httpdOutput(r, "ERROR.");
		return;
	}

	ptr = strstr(r->request.query, "url=http:");
	protocol = 1;
	if(!ptr){
		ptr = strstr(r->request.query, "url=https:");
		protocol = 2;
	}

	if ( !ptr){
		httpdOutput(r, "OK.");
		return;
	}

	ops = strstr(ptr, ":");

	if(!ops){
		httpdOutput(r, "OK.");
		return;
	}


	switch(protocol){
	case 1:
		snprintf(url, HTTP_MAX_URL - 1, "http:/%s", ++ops);
		break;
	default:
		snprintf(url, HTTP_MAX_URL - 1, "https:/%s", ++ops);
		break;
	}


	debug(LOG_DEBUG, "Function: http_callback_allow_redirect URL: [ %s ] ", url);

	http_send_redirect(r, url, "allow redirecting");

    return;
}

void http_callback_auth_null(httpd * webserver, request * r)
{
	return;
}

void http_callback_auth(httpd * webserver, request * r)
{

}

void http_callback_disconnect(httpd * webserver, request * r)
{

}


void
send_http_page(request * r, const char *title, const char *message)
{
    s_config *config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;

    fd = open(config->htmlmsgfile, O_RDONLY);
    if (fd == -1) {
        debug(LOG_CRIT, "Failed to open HTML message file %s: %s", config->htmlmsgfile, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info) == -1) {
        debug(LOG_CRIT, "Failed to stat HTML message file: %s", strerror(errno));
        close(fd);
        return;
    }
    // Cast from long to unsigned int
    buffer = (char *)safe_malloc((size_t) stat_info.st_size + 1);
    written = read(fd, buffer, (size_t) stat_info.st_size);
    if (written == -1) {
        debug(LOG_CRIT, "Failed to read HTML message file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);

    buffer[written] = 0;
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
    httpdAddVariable(r, "nodeID", config->gw_id);
    httpdOutput(r, buffer);
    free(buffer);
}
