/*********************************************************************************************************
 * Running-config export and peer snippet import (PrettyDiameter)
 *********************************************************************************************************/

#include "fdcore-internal.h"
#include <stdio.h>
#include <time.h>
#include <ctype.h>

static int ep_fprint_conf(FILE *f, const char *kw, struct fd_list *eps)
{
	struct fd_list *li;

	if (!f || !kw || !eps)
		return EINVAL;

	for (li = eps->next; li != eps; li = li->next) {
		struct fd_endpoint * ep = (struct fd_endpoint *)li;
		char host[INET6_ADDRSTRLEN];

		if (!(ep->flags & EP_FL_CONF))
			continue;
		if (getnameinfo(&ep->sa, sSAlen(&ep->sa), host, sizeof(host), NULL, 0, NI_NUMERICHOST))
			continue;
		fprintf(f, "    %s = \"%s\";\n", kw, host);
	}
	return 0;
}

static const char * mode_str(unsigned mode)
{
	switch (mode) {
	case PI_MODE_CLIENT: return "client";
	case PI_MODE_SERVER: return "server";
	case PI_MODE_BOTH:   return "both";
	default:             return NULL;
	}
}

static int peer_fprint_connectpeer(FILE *f, struct fd_peer * peer)
{
	const char *ms;
	int st;

	if (!f || !CHECK_PEER(peer))
		return EINVAL;

	st = fd_peer_getstate(&peer->p_hdr);
	fprintf(f, "# state: %s", STATE_STR(st));
	if (peer->p_flags.pf_listen)
		fprintf(f, ", listener: active");
	fprintf(f, "\n");
	fprintf(f, "ConnectPeer = \"%s\" {\n", peer->p_hdr.info.pi_diamid);

	ep_fprint_conf(f, "ConnectTo", &peer->p_hdr.info.pi_endpoints);
	ep_fprint_conf(f, "SrcIP", &peer->p_hdr.info.pi_src_endpoints);

	if (peer->p_hdr.info.config.pic_port)
		fprintf(f, "    Port = %u;\n", (unsigned)peer->p_hdr.info.config.pic_port);
	if (peer->p_hdr.info.config.pic_src_port)
		fprintf(f, "    SrcPort = %u;\n", (unsigned)peer->p_hdr.info.config.pic_src_port);

	ms = mode_str(peer->p_hdr.info.config.pic_flags.mode);
	if (ms)
		fprintf(f, "    Mode = %s;\n", ms);

	if (peer->p_hdr.info.config.pic_realm)
		fprintf(f, "    Realm = \"%s\";\n", peer->p_hdr.info.config.pic_realm);
	if (peer->p_hdr.info.config.pic_local_host)
		fprintf(f, "    LocalHost = \"%s\";\n", peer->p_hdr.info.config.pic_local_host);
	if (peer->p_hdr.info.config.pic_local_realm)
		fprintf(f, "    LocalRealm = \"%s\";\n", peer->p_hdr.info.config.pic_local_realm);

	if (peer->p_hdr.info.config.pic_flags.pro3 == PI_P3_IP)
		fprintf(f, "    No_IPv6;\n");
	if (peer->p_hdr.info.config.pic_flags.pro3 == PI_P3_IPv6)
		fprintf(f, "    No_IP;\n");
	if (peer->p_hdr.info.config.pic_flags.pro4 == PI_P4_SCTP)
		fprintf(f, "    No_TCP;\n");
	if (peer->p_hdr.info.config.pic_flags.pro4 == PI_P4_TCP)
		fprintf(f, "    No_SCTP;\n");
	if (peer->p_hdr.info.config.pic_flags.alg == PI_ALGPREF_TCP)
		fprintf(f, "    Prefer_TCP;\n");
	if (peer->p_hdr.info.config.pic_flags.sec & PI_SEC_NONE)
		fprintf(f, "    No_TLS;\n");
	if (peer->p_hdr.info.config.pic_flags.sec & PI_SEC_TLS_OLD)
		fprintf(f, "    TLS_old_method;\n");
	if (peer->p_hdr.info.config.pic_flags.sctpsec & PI_SCTPSEC_3436)
		fprintf(f, "    Sec3436;\n");

	fprintf(f, "};\n\n");
	return 0;
}

/* Export Identity/Realm/ListenOn and all ConnectPeer blocks from running state */
int fd_conf_export_running(FILE * out)
{
	struct fd_list * li;
	time_t now;
	struct tm tm_buf;
	char tstr[64];

	TRACE_ENTRY("%p", out);
	CHECK_PARAMS(out && fd_g_config);

	time(&now);
	gmtime_r(&now, &tm_buf);
	strftime(tstr, sizeof(tstr), "%Y-%m-%d %H:%M:%S UTC", &tm_buf);

	fprintf(out, "# PrettyDiameter running config export — %s\n", tstr);
	fprintf(out, "# Source file at startup: %s\n\n", fd_g_config->cnf_file ?: "(unknown)");

	if (fd_g_config->cnf_diamid)
		fprintf(out, "Identity = \"%s\";\n", fd_g_config->cnf_diamid);
	if (fd_g_config->cnf_diamrlm)
		fprintf(out, "Realm = \"%s\";\n", fd_g_config->cnf_diamrlm);
	if (fd_g_config->cnf_port)
		fprintf(out, "Port = %u;\n", (unsigned)fd_g_config->cnf_port);
	if (fd_g_config->cnf_port_tls)
		fprintf(out, "SecPort = %u;\n", (unsigned)fd_g_config->cnf_port_tls);

	if (!FD_IS_LIST_EMPTY(&fd_g_config->cnf_endpoints)) {
		fprintf(out, "# ListenOn\n");
		ep_fprint_conf(out, "ListenOn", &fd_g_config->cnf_endpoints);
	}
	fprintf(out, "\n");

	CHECK_FCT( pthread_rwlock_rdlock(&fd_g_peers_rw) );
	for (li = fd_g_peers.next; li != &fd_g_peers; li = li->next)
		CHECK_FCT_DO( peer_fprint_connectpeer(out, (struct fd_peer *)li), break );
	CHECK_FCT( pthread_rwlock_unlock(&fd_g_peers_rw) );

	return 0;
}

int fd_conf_export_running_path(const char * path)
{
	FILE * f;
	int ret;

	TRACE_ENTRY("%p", path);
	CHECK_PARAMS(path);

	f = fopen(path, "w");
	if (!f)
		return errno;

	ret = fd_conf_export_running(f);
	if (fclose(f) && !ret)
		ret = errno;
	return ret;
}

static char * trim(char * s)
{
	char * e;
	if (!s)
		return s;
	while (*s && isspace((unsigned char)*s))
		s++;
	e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		e--;
	*e = '\0';
	return s;
}

static int add_endpoint(struct peer_info * info, const char * addr, int src)
{
	struct addrinfo hints, *ai, *aip;
	int ret;
	struct fd_list * list = src ? &info->pi_src_endpoints : &info->pi_endpoints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;
	ret = getaddrinfo(addr, NULL, &hints, &ai);
	if (ret) {
		hints.ai_flags = AI_ADDRCONFIG;
		ret = getaddrinfo(addr, NULL, &hints, &ai);
	}
	if (ret)
		return EINVAL;

	for (aip = ai; aip; aip = aip->ai_next)
		CHECK_FCT( fd_ep_add_merge(list, aip->ai_addr, aip->ai_addrlen, EP_FL_CONF) );
	freeaddrinfo(ai);
	return 0;
}

/* Import one peer from a simple key=value file (see doc/dra_peerctl.conf.sample) */
int fd_peer_add_from_conf_file(const char * path)
{
	FILE * f;
	char line[512];
	struct peer_info info;
	char * diamid = NULL;
	char * key, * val;
	int ret = 0;

	TRACE_ENTRY("%p", path);
	CHECK_PARAMS(path);

	f = fopen(path, "r");
	if (!f)
		return errno;

	memset(&info, 0, sizeof(info));
	info.config.pic_flags.persist = PI_PRST_ALWAYS;
	fd_list_init(&info.pi_endpoints, NULL);
	fd_list_init(&info.pi_src_endpoints, NULL);

	while (fgets(line, sizeof(line), f)) {
		char * p = trim(line);
		if (!*p || *p == '#')
			continue;

		key = p;
		val = strchr(p, '=');
		if (!val)
			continue;
		*val++ = '\0';
		key = trim(key);
		val = trim(val);
		{
			size_t vn = strlen(val);
			if (vn && val[vn - 1] == ';')
				val[vn - 1] = '\0';
		}
		while (*val == '"' || *val == '\'') {
			size_t n = strlen(val);
			if (n >= 2 && val[n-1] == val[0]) {
				val[n-1] = '\0';
				val++;
			}
			break;
		}

		if (!strcasecmp(key, "DiameterId") || !strcasecmp(key, "ConnectPeer")) {
			CHECK_MALLOC( diamid = strdup(val) );
		} else if (!strcasecmp(key, "ConnectTo")) {
			CHECK_FCT(add_endpoint(&info, val, 0));
		} else if (!strcasecmp(key, "SrcIP")) {
			CHECK_FCT(add_endpoint(&info, val, 1));
		} else if (!strcasecmp(key, "Port")) {
			info.config.pic_port = (uint16_t)atoi(val);
		} else if (!strcasecmp(key, "SrcPort")) {
			info.config.pic_src_port = (uint16_t)atoi(val);
		} else if (!strcasecmp(key, "Mode")) {
			if (!strcasecmp(val, "client"))
				info.config.pic_flags.mode = PI_MODE_CLIENT;
			else if (!strcasecmp(val, "server"))
				info.config.pic_flags.mode = PI_MODE_SERVER;
			else if (!strcasecmp(val, "both"))
				info.config.pic_flags.mode = PI_MODE_BOTH;
		} else if (!strcasecmp(key, "Realm")) {
			CHECK_MALLOC( info.config.pic_realm = strdup(val) );
		} else if (!strcasecmp(key, "LocalHost")) {
			CHECK_MALLOC( info.config.pic_local_host = strdup(val) );
		} else if (!strcasecmp(key, "LocalRealm")) {
			CHECK_MALLOC( info.config.pic_local_realm = strdup(val) );
		} else if (!strcasecmp(key, "No_TLS")) {
			info.config.pic_flags.sec |= PI_SEC_NONE;
		} else if (!strcasecmp(key, "No_TCP")) {
			info.config.pic_flags.pro4 = PI_P4_SCTP;
		} else if (!strcasecmp(key, "No_SCTP")) {
			info.config.pic_flags.pro4 = PI_P4_TCP;
		} else if (!strcasecmp(key, "Prefer_TCP")) {
			info.config.pic_flags.alg = PI_ALGPREF_TCP;
		}
	}

	fclose(f);

	if (!diamid) {
		ret = EINVAL;
		goto cleanup;
	}
	info.pi_diamid = diamid;
	ret = fd_peer_add(&info, path, NULL, NULL);

cleanup:
	free(diamid);
	free(info.config.pic_realm);
	free(info.config.pic_local_host);
	free(info.config.pic_local_realm);
	while (!FD_IS_LIST_EMPTY(&info.pi_endpoints)) {
		struct fd_list * li = info.pi_endpoints.next;
		fd_list_unlink(li);
		free(li);
	}
	while (!FD_IS_LIST_EMPTY(&info.pi_src_endpoints)) {
		struct fd_list * li = info.pi_src_endpoints.next;
		fd_list_unlink(li);
		free(li);
	}
	return ret;
}
