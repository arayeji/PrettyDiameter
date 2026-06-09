/*********************************************************************************************************
 * dra_peerctl — HTTP control API for peer add/remove/list and running-config export
 *********************************************************************************************************/

#include <freeDiameter/extension.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MODULE_NAME "dra_peerctl"
#define DEFAULT_PORT 9069
#define DEFAULT_BIND "127.0.0.1"
#define REQ_MAX (256 * 1024)

static uint16_t ctl_port = DEFAULT_PORT;
static char ctl_bind[64] = DEFAULT_BIND;
static int ctl_sock = -1;
static volatile int ctl_run;
static pthread_t ctl_thr;

static int url_decode(char *s)
{
	char *r = s, *w = s;
	while (*r) {
		if (*r == '%' && isxdigit((unsigned char)r[1]) && isxdigit((unsigned char)r[2])) {
			char hex[3] = { r[1], r[2], 0 };
			*w++ = (char)strtol(hex, NULL, 16);
			r += 3;
		} else if (*r == '+') {
			*w++ = ' ';
			r++;
		} else {
			*w++ = *r++;
		}
	}
	*w = '\0';
	return 0;
}

static const char * query_param(const char *q, const char *key, char *buf, size_t bufsz)
{
	size_t klen = strlen(key);
	if (!q || !*q)
		return NULL;
	while (*q) {
		const char * amp = strchr(q, '&');
		size_t seglen = amp ? (size_t)(amp - q) : strlen(q);
		if (seglen > klen + 1 && !strncmp(q, key, klen) && q[klen] == '=') {
			size_t vlen = seglen - klen - 1;
			if (vlen >= bufsz)
				vlen = bufsz - 1;
			memcpy(buf, q + klen + 1, vlen);
			buf[vlen] = '\0';
			url_decode(buf);
			return buf;
		}
		if (!amp)
			break;
		q = amp + 1;
	}
	return NULL;
}

static void http_reply(int fd, int code, const char * ctype, const char * body)
{
	char hdr[512];
	size_t blen = body ? strlen(body) : 0;
	const char * status = (code == 200) ? "OK" : (code == 400) ? "Bad Request" :
		(code == 404) ? "Not Found" : (code == 409) ? "Conflict" :
		(code == 500) ? "Internal Server Error" : "Error";

	snprintf(hdr, sizeof(hdr),
		"HTTP/1.0 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
		code, status, ctype, blen);
	send(fd, hdr, strlen(hdr), 0);
	if (body && blen)
		send(fd, body, blen, 0);
}

static char * build_list(void)
{
	struct fd_list * li;
	char * buf = NULL;
	size_t len = 0, off = 0;

	CHECK_MALLOC( buf = malloc(256) );
	buf[0] = '\0';

	CHECK_FCT( pthread_rwlock_rdlock(&fd_g_peers_rw) );
	for (li = fd_g_peers.next; li != &fd_g_peers; li = li->next) {
		struct fd_peer * p = (struct fd_peer *)li;
		int st = fd_peer_getstate(&p->p_hdr);
		CHECK_MALLOC_DO( fd_dump_extend(&buf, &len, &off,
			"%s\t%s\t%s%s\n",
			p->p_hdr.info.pi_diamid,
			STATE_STR(st),
			p->p_flags.pf_listen ? "listen " : "",
			fd_peer_mode_wants_client(&p->p_hdr.info) ? "client" : "server-only"),
			break );
	}
	CHECK_FCT( pthread_rwlock_unlock(&fd_g_peers_rw) );
	return buf;
}

static char * build_dump(void)
{
	FILE * mem;
	char * buf = NULL;
	size_t sz = 0;

	mem = open_memstream(&buf, &sz);
	if (!mem)
		return NULL;
	if (fd_conf_export_running(mem) != 0) {
		fclose(mem);
		free(buf);
		return strdup("# export failed\n");
	}
	fclose(mem);
	return buf;
}

static int handle_add_body(const char * body, size_t bodylen)
{
	char tmpl[] = "/tmp/fd-peer-XXXXXX";
	int fd;
	FILE * f;

	if (!bodylen || bodylen > REQ_MAX)
		return EINVAL;

	fd = mkstemp(tmpl);
	if (fd < 0)
		return errno;
	f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		unlink(tmpl);
		return errno;
	}
	if (fwrite(body, 1, bodylen, f) != bodylen) {
		fclose(f);
		unlink(tmpl);
		return EIO;
	}
	fclose(f);

	{
		int ret = fd_peer_add_from_conf_file(tmpl);
		unlink(tmpl);
		return ret;
	}
}

static void serve_client(int cfd)
{
	char req[8192];
	char method[16], path[512], ver[16];
	ssize_t n, total = 0;
	char * body = NULL;
	char * body_heap = NULL;
	size_t bodylen = 0, content_length = 0;
	char * qmark, * line_end;
	char peer_buf[512];
	char force_buf[16];
	int force = 0, ret;

	while (total < (ssize_t)sizeof(req) - 1) {
		n = recv(cfd, req + total, sizeof(req) - 1 - total, 0);
		if (n <= 0)
			return;
		total += n;
		req[total] = '\0';
		line_end = strstr(req, "\r\n\r\n");
		if (line_end)
			break;
	}
	if (!line_end)
		return;

	if (sscanf(req, "%15s %511s %15s", method, path, ver) != 3) {
		http_reply(cfd, 400, "text/plain", "bad request\n");
		return;
	}

	qmark = strchr(path, '?');
	if (qmark)
		*qmark++ = '\0';

	{
		char * cl = strstr(req, "Content-Length:");
		if (cl) {
			cl += 15;
			while (*cl == ' ')
				cl++;
			content_length = (size_t)strtoul(cl, NULL, 10);
		}
	}

	if (content_length > 0) {
		char * body_start = line_end + 4;
		bodylen = (size_t)(req + total - body_start);
		if (bodylen < content_length) {
			body_heap = malloc(content_length + 1);
			if (!body_heap) {
				http_reply(cfd, 500, "text/plain", "oom\n");
				return;
			}
			memcpy(body_heap, body_start, bodylen);
			while (bodylen < content_length) {
				n = recv(cfd, body_heap + bodylen, content_length - bodylen, 0);
				if (n <= 0) {
					free(body_heap);
					return;
				}
				bodylen += (size_t)n;
			}
			body_heap[bodylen] = '\0';
			body = body_heap;
		} else {
			body = body_start;
			bodylen = content_length;
		}
	}

	if (!strcasecmp(method, "GET") && !strcmp(path, "/")) {
		http_reply(cfd, 200, "text/plain",
			"dra_peerctl: GET /list | GET /dump | POST /remove?peer=ID&force=0|1 | POST /add (snippet body)\n");
	} else if (!strcasecmp(method, "GET") && !strcmp(path, "/list")) {
		char * list = build_list();
		http_reply(cfd, 200, "text/plain", list ?: "error\n");
		free(list);
	} else if (!strcasecmp(method, "GET") && !strcmp(path, "/dump")) {
		char * dump = build_dump();
		http_reply(cfd, 200, "text/plain", dump ?: "# error\n");
		free(dump);
	} else if (!strcasecmp(method, "POST") && !strcmp(path, "/remove")) {
		if (!query_param(qmark, "peer", peer_buf, sizeof(peer_buf))) {
			http_reply(cfd, 400, "text/plain", "missing peer= query parameter\n");
			goto out;
		}
		if (query_param(qmark, "force", force_buf, sizeof(force_buf)) && atoi(force_buf))
			force = 1;
		ret = fd_peer_remove_byid(peer_buf, strlen(peer_buf), 1, force);
		if (ret == 0)
			http_reply(cfd, 200, "text/plain", "removed\n");
		else if (ret == ENOENT)
			http_reply(cfd, 404, "text/plain", "peer not found\n");
		else if (ret == ETIMEDOUT)
			http_reply(cfd, 409, "text/plain", "timeout (retry with force=1)\n");
		else
			http_reply(cfd, 500, "text/plain", "remove failed\n");
	} else if (!strcasecmp(method, "POST") && !strcmp(path, "/add")) {
		if (!body || !bodylen) {
			http_reply(cfd, 400, "text/plain", "POST snippet body required\n");
			goto out;
		}
		ret = handle_add_body(body, bodylen);
		if (ret == 0)
			http_reply(cfd, 200, "text/plain", "added\n");
		else if (ret == EEXIST)
			http_reply(cfd, 409, "text/plain", "peer already exists\n");
		else
			http_reply(cfd, 500, "text/plain", "add failed\n");
	} else {
		http_reply(cfd, 404, "text/plain", "not found\n");
	}

out:
	free(body_heap);
}

static void * ctl_thread(void * arg)
{
	(void)arg;
	fd_log_threadname("dra_peerctl");

	while (ctl_run) {
		struct sockaddr_in cli;
		socklen_t sl = sizeof(cli);
		int cfd = accept(ctl_sock, (struct sockaddr *)&cli, &sl);
		if (cfd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		serve_client(cfd);
		close(cfd);
	}
	return NULL;
}

static int conf_load(char * conffile)
{
	FILE * f;
	char line[512], * p, * val;

	if (conffile) {
		f = fopen(conffile, "r");
		if (!f)
			return 0;
		while (fgets(line, sizeof(line), f)) {
			p = line;
			while (*p == ' ' || *p == '\t')
				p++;
			if (*p == '#' || *p == '\n')
				continue;
			val = strchr(p, '=');
			if (!val)
				continue;
			*val++ = '\0';
			while (*val == ' ')
				val++;
			if (!strcasecmp(p, "Port"))
				ctl_port = (uint16_t)atoi(val);
			else if (!strcasecmp(p, "Bind")) {
				char * q = val;
				while (*q && *q != ';' && *q != '\n' && *q != '\r') q++;
				*q = '\0';
				while (*val == '"' || *val == '\'') val++;
				if (val[strlen(val)-1] == '"' || val[strlen(val)-1] == '\'')
					val[strlen(val)-1] = '\0';
				strncpy(ctl_bind, val, sizeof(ctl_bind) - 1);
			}
		}
		fclose(f);
	}
	return 0;
}

static int ctl_start(void)
{
	struct sockaddr_in sin;
	int on = 1;

	ctl_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (ctl_sock < 0)
		return errno;

	setsockopt(ctl_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(ctl_port);
	if (inet_pton(AF_INET, ctl_bind, &sin.sin_addr) != 1) {
		close(ctl_sock);
		ctl_sock = -1;
		return EINVAL;
	}

	if (bind(ctl_sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		close(ctl_sock);
		ctl_sock = -1;
		return errno;
	}
	if (listen(ctl_sock, 8) < 0) {
		close(ctl_sock);
		ctl_sock = -1;
		return errno;
	}

	ctl_run = 1;
	CHECK_POSIX(pthread_create(&ctl_thr, NULL, ctl_thread, NULL));
	fd_log_notice("%s: control HTTP on %s:%u (GET /list, /dump; POST /remove, /add)",
		MODULE_NAME, ctl_bind, (unsigned)ctl_port);
	return 0;
}

static void ctl_stop(void)
{
	ctl_run = 0;
	if (ctl_sock >= 0) {
		close(ctl_sock);
		ctl_sock = -1;
	}
	if (ctl_thr) {
		pthread_cancel(ctl_thr);
		pthread_join(ctl_thr, NULL);
		ctl_thr = (pthread_t)0;
	}
}

static int dra_peerctl_main(char * conffile)
{
	TRACE_ENTRY("%p", conffile);
	CHECK_FCT(conf_load(conffile));
	CHECK_FCT(ctl_start());
	return 0;
}

void fd_ext_fini(void)
{
	ctl_stop();
}

EXTENSION_ENTRY("dra_peerctl", dra_peerctl_main);
