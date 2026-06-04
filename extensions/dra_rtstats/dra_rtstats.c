/*********************************************************************************************************
 * DRA relay statistics — per-direction / peer / realm / command counters + simple HTTP page.
 * Do not use dbg_msg_dumps on production nodes; this extension is lightweight (no message dumps).
 *********************************************************************************************************/

#include <freeDiameter/extension.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <errno.h>
#include <ctype.h>
#include <regex.h>

#include "../rt_redirect/uthash.h"

#define MODULE_NAME "dra_rtstats"
#define DEFAULT_PORT 8088
#define KEYLEN 640
#define LABELLEN 64
#define REALMLEN 128
#define PEERLEN 256
#define CMDLEN 48
#define CODELEN 16
#define CRITLEN 128

struct label_map {
	struct fd_list chain;
	char *match;
	char *label;
};

struct stats_row {
	char key[KEYLEN];
	char dir[8];
	char oper[LABELLEN];
	char link[LABELLEN];
	char peer[PEERLEN];
	char orealm[REALMLEN];
	char drealm[REALMLEN];
	char cmd[CMDLEN];
	char msg_code[CODELEN];
	uint64_t count;
	UT_hash_handle hh;
};

struct stats_snap {
	char dir[8];
	char oper[LABELLEN];
	char link[LABELLEN];
	char peer[PEERLEN];
	char orealm[REALMLEN];
	char drealm[REALMLEN];
	char cmd[CMDLEN];
	char msg_code[CODELEN];
	uint64_t count;
};

struct link_peer_snap {
	char peer[PEERLEN];
	char link[LABELLEN];
	int up;
	uint64_t in_cnt;
	uint64_t out_cnt;
};

struct link_realm_snap {
	char dir[8];
	char orealm[REALMLEN];
	char drealm[REALMLEN];
	uint64_t count;
};

struct link_msg_snap {
	char dir[8];
	char cmd[CMDLEN];
	char msg_code[CODELEN];
	uint64_t count;
};

struct global_msg_snap {
	char cmd[CMDLEN];
	char msg_code[CODELEN];
	uint64_t in_cnt;
	uint64_t out_cnt;
};

enum route_crit_type {
	ROUTE_CRI_ALL = 0,
	ROUTE_CRI_UN,
	ROUTE_CRI_DR,
	ROUTE_CRI_DH,
	ROUTE_CRI_OH,
	ROUTE_CRI_OR,
};

struct route_rule {
	struct fd_list chain;
	char label[LABELLEN];
	enum route_crit_type crit;
	char crit_desc[CRITLEN];
	char *crit_val;
	int crit_regex;
	regex_t crit_preg;
	char target[PEERLEN];
};

struct route_stats_row {
	char key[KEYLEN];
	char label[LABELLEN];
	char crit_desc[CRITLEN];
	char target[PEERLEN];
	uint64_t match_count;
	uint64_t routed_count;
	UT_hash_handle hh;
};

struct route_stats_snap {
	char label[LABELLEN];
	char crit_desc[CRITLEN];
	char target[PEERLEN];
	uint64_t match_count;
	uint64_t routed_count;
};

static struct stats_row *stats_head = NULL;
static struct route_stats_row *route_stats_head = NULL;
static struct fd_list route_rules = FD_LIST_INITIALIZER(route_rules);
static pthread_rwlock_t stats_lock = PTHREAD_RWLOCK_INITIALIZER;

static struct fd_list realm_labels = FD_LIST_INITIALIZER(realm_labels);
static struct fd_list peer_labels = FD_LIST_INITIALIZER(peer_labels);

struct dh_replace_map {
	struct fd_list chain;
	char *from;
	char *to;
	size_t from_len;
	size_t to_len;
};

static struct fd_list dh_replace_list = FD_LIST_INITIALIZER(dh_replace_list);
static struct dict_object *dh_avp_model = NULL;

static uint16_t http_port = DEFAULT_PORT;
static int http_sock = -1;
static pthread_t http_thr;
static volatile int http_run = 0;
static struct fd_hook_hdl *stats_hdl = NULL;
static struct fd_rt_out_hdl *route_rt_hdl = NULL;
static struct fd_rt_fwd_hdl *dh_replace_hdl = NULL;

static void label_maps_free(struct fd_list *list)
{
	while (!FD_IS_LIST_EMPTY(list)) {
		struct fd_list *li = list->next;
		struct label_map *m = (struct label_map *)li;
		fd_list_unlink(li);
		free(m->match);
		free(m->label);
		free(m);
	}
}

static char *lookup_label(struct fd_list *list, const char *haystack)
{
	struct fd_list *li;
	size_t hlen;
	if (!haystack)
		return NULL;
	hlen = strlen(haystack);
	for (li = list->next; li != list; li = li->next) {
		struct label_map *m = (struct label_map *)li;
		size_t mlen = strlen(m->match);
		size_t i;
		if (mlen > hlen)
			continue;
		for (i = 0; i <= hlen - mlen; i++) {
			if (!strncasecmp(haystack + i, m->match, mlen))
				return m->label;
		}
	}
	return NULL;
}

static int add_label(struct fd_list *list, char *match, char *label)
{
	struct label_map *m;
	CHECK_MALLOC(m = calloc(1, sizeof(*m)));
	CHECK_MALLOC(m->match = strdup(match));
	CHECK_MALLOC(m->label = strdup(label));
	fd_list_init(&m->chain, m);
	fd_list_insert_before(list, &m->chain);
	return 0;
}

static char *trim_space(char *s)
{
	char *e;
	while (*s && isspace((unsigned char)*s))
		s++;
	e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = '\0';
	return s;
}

static void strip_quotes(char *s)
{
	size_t len;
	s = trim_space(s);
	len = strlen(s);
	if (len >= 2 && ((s[0] == '"' && s[len - 1] == '"') || (s[0] == '\'' && s[len - 1] == '\''))) {
		s[len - 1] = '\0';
		memmove(s, s + 1, len - 1);
	}
}

static void dh_replace_list_free(void)
{
	while (!FD_IS_LIST_EMPTY(&dh_replace_list)) {
		struct fd_list *li = dh_replace_list.next;
		struct dh_replace_map *m = (struct dh_replace_map *)li;
		fd_list_unlink(li);
		free(m->from);
		free(m->to);
		free(m);
	}
}

static int dh_replace_add(char *from, char *to)
{
	struct dh_replace_map *m;

	from = trim_space(from);
	to = trim_space(to);
	strip_quotes(from);
	strip_quotes(to);
	if (!from[0] || !to[0])
		return EINVAL;

	CHECK_MALLOC(m = calloc(1, sizeof(*m)));
	CHECK_MALLOC(m->from = strdup(from));
	CHECK_MALLOC(m->to = strdup(to));
	m->from_len = strlen(m->from);
	m->to_len = strlen(m->to);
	fd_list_init(&m->chain, m);
	fd_list_insert_before(&dh_replace_list, &m->chain);
	fd_log_notice("%s: dh_replace %s -> %s", MODULE_NAME, m->from, m->to);
	return 0;
}

static int dh_replace_fwd_cb(void *cbdata, struct msg **msg)
{
	struct avp *avp = NULL;
	struct avp_hdr *hdr;
	struct fd_list *li;

	(void)cbdata;

	if (FD_IS_LIST_EMPTY(&dh_replace_list) || !dh_avp_model)
		return 0;

	if (fd_msg_search_avp(*msg, dh_avp_model, &avp) || !avp)
		return 0;
	CHECK_FCT(fd_msg_avp_hdr(avp, &hdr));
	if (!hdr->avp_value)
		return 0;

	for (li = dh_replace_list.next; li != &dh_replace_list; li = li->next) {
		struct dh_replace_map *m = (struct dh_replace_map *)li;
		union avp_value nval;

		if (fd_os_almostcasesrch(hdr->avp_value->os.data, hdr->avp_value->os.len,
				m->from, m->from_len, NULL))
			continue;

		fd_log_notice("%s: rewriting Destination-Host %.*s -> %s", MODULE_NAME,
			(int)hdr->avp_value->os.len, (char *)hdr->avp_value->os.data, m->to);
		memset(&nval, 0, sizeof(nval));
		nval.os.data = (uint8_t *)m->to;
		nval.os.len = m->to_len;
		CHECK_FCT(fd_msg_avp_setvalue(avp, &nval));
		break;
	}

	return 0;
}

static int crit_type_from_name(const char *name, enum route_crit_type *out)
{
	if (!strcasecmp(name, "un")) {
		*out = ROUTE_CRI_UN;
		return 0;
	}
	if (!strcasecmp(name, "dr")) {
		*out = ROUTE_CRI_DR;
		return 0;
	}
	if (!strcasecmp(name, "dh")) {
		*out = ROUTE_CRI_DH;
		return 0;
	}
	if (!strcasecmp(name, "oh")) {
		*out = ROUTE_CRI_OH;
		return 0;
	}
	if (!strcasecmp(name, "or")) {
		*out = ROUTE_CRI_OR;
		return 0;
	}
	return EINVAL;
}

static int route_rule_compile(struct route_rule *rule)
{
	if (!rule->crit_regex || !rule->crit_val)
		return 0;
	if (regcomp(&rule->crit_preg, rule->crit_val, REG_EXTENDED | REG_NOSUB)) {
		fd_log_error("%s: invalid route regex '%s' for '%s'", MODULE_NAME,
				rule->crit_val, rule->label);
		return EINVAL;
	}
	return 0;
}

static void route_rules_free(void)
{
	while (!FD_IS_LIST_EMPTY(&route_rules)) {
		struct route_rule *rule = (struct route_rule *)route_rules.next;
		fd_list_unlink(&rule->chain);
		if (rule->crit_regex)
			regfree(&rule->crit_preg);
		free(rule->crit_val);
		free(rule);
	}
}

static void route_stats_seed_rule(struct route_rule *rule);

static int route_rule_add(const char *label, const char *crit_raw, const char *target_raw)
{
	struct route_rule *rule;
	char critbuf[256];
	char *eq;
	const char *crit = crit_raw;

	CHECK_MALLOC(rule = calloc(1, sizeof(*rule)));
	fd_list_init(&rule->chain, rule);
	snprintf(rule->label, sizeof(rule->label), "%s", label);

	if (!crit || !*crit || !strcmp(crit, "*")) {
		snprintf(rule->crit_desc, sizeof(rule->crit_desc), "*");
		rule->crit = ROUTE_CRI_ALL;
	} else {
		strncpy(critbuf, crit, sizeof(critbuf) - 1);
		critbuf[sizeof(critbuf) - 1] = '\0';
		eq = strchr(critbuf, '=');
		if (!eq) {
			free(rule);
			return EINVAL;
		}
		*eq++ = '\0';
		if (crit_type_from_name(trim_space(critbuf), &rule->crit) != 0) {
			free(rule);
			return EINVAL;
		}
		eq = trim_space(eq);
		if (*eq == '[') {
			char *end = strrchr(eq, ']');
			if (!end) {
				free(rule);
				return EINVAL;
			}
			*end = '\0';
			eq++;
			rule->crit_regex = 1;
		}
		strip_quotes(eq);
		CHECK_MALLOC(rule->crit_val = strdup(eq));
		snprintf(rule->crit_desc, sizeof(rule->crit_desc), "%.*s",
				(int)(sizeof(rule->crit_desc) - 1), crit);
		if (route_rule_compile(rule) != 0) {
			free(rule->crit_val);
			free(rule);
			return EINVAL;
		}
	}

	if (target_raw && *target_raw) {
		char tbuf[PEERLEN];
		strncpy(tbuf, target_raw, sizeof(tbuf) - 1);
		tbuf[sizeof(tbuf) - 1] = '\0';
		strip_quotes(tbuf);
		if (strcmp(tbuf, "*") != 0)
			snprintf(rule->target, sizeof(rule->target), "%s", tbuf);
	} else {
		rule->target[0] = '\0';
	}

	fd_list_insert_before(&route_rules, &rule->chain);
	fd_log_notice("%s: route rule '%s' (%s) -> '%s'", MODULE_NAME,
			rule->label, rule->crit_desc, rule->target[0] ? rule->target : "*");
	route_stats_seed_rule(rule);
	return 0;
}

/* Pre-create stats rows so the HTTP report lists every configured route_match rule (even 0 matches). */
static void route_stats_seed_rule(struct route_rule *rule)
{
	struct route_stats_row *row = NULL;
	char key[KEYLEN];

	if (!rule)
		return;

	snprintf(key, sizeof(key), "%s|%s|%s", rule->label, rule->crit_desc,
			rule->target[0] ? rule->target : "*");

	CHECK_POSIX(pthread_rwlock_wrlock(&stats_lock));
	HASH_FIND_STR(route_stats_head, key, row);
	if (!row) {
		CHECK_MALLOC_DO(row = calloc(1, sizeof(*row)), {
			pthread_rwlock_unlock(&stats_lock);
			return;
		});
		strncpy(row->key, key, sizeof(row->key) - 1);
		strncpy(row->label, rule->label, sizeof(row->label) - 1);
		strncpy(row->crit_desc, rule->crit_desc, sizeof(row->crit_desc) - 1);
		strncpy(row->target, rule->target[0] ? rule->target : "*", sizeof(row->target) - 1);
		HASH_ADD_STR(route_stats_head, key, row);
	}
	CHECK_POSIX(pthread_rwlock_unlock(&stats_lock));
}

static int route_match_parse_line(char *val)
{
	char *p1, *p2, *p3, *save = NULL;
	char label[LABELLEN];

	p1 = strtok_r(val, "|", &save);
	p2 = strtok_r(NULL, "|", &save);
	p3 = strtok_r(NULL, "|", &save);
	if (!p1 || !p2)
		return EINVAL;

	strncpy(label, trim_space(p1), sizeof(label) - 1);
	label[sizeof(label) - 1] = '\0';
	strip_quotes(label);
	if (!label[0])
		return EINVAL;

	return route_rule_add(label, trim_space(p2), p3 ? trim_space(p3) : "");
}

static int avp_code_for_crit(enum route_crit_type crit)
{
	switch (crit) {
	case ROUTE_CRI_UN: return AC_USER_NAME;
	case ROUTE_CRI_DR: return AC_DESTINATION_REALM;
	case ROUTE_CRI_DH: return AC_DESTINATION_HOST;
	case ROUTE_CRI_OH: return AC_ORIGIN_HOST;
	case ROUTE_CRI_OR: return AC_ORIGIN_REALM;
	default: return -1;
	}
}

static int msg_get_avp_str(struct msg *msg, enum route_crit_type crit, char *buf, size_t blen)
{
	struct avp *avp = NULL;
	struct avp_hdr *hdr;
	struct dict_object *model = NULL;
	int code;
	const char *name;

	buf[0] = '\0';
	if (crit == ROUTE_CRI_ALL)
		return 0;

	code = avp_code_for_crit(crit);
	switch (crit) {
	case ROUTE_CRI_UN: name = "User-Name"; break;
	case ROUTE_CRI_DR: name = "Destination-Realm"; break;
	case ROUTE_CRI_DH: name = "Destination-Host"; break;
	case ROUTE_CRI_OH: name = "Origin-Host"; break;
	case ROUTE_CRI_OR: name = "Origin-Realm"; break;
	default: return ENOENT;
	}

	if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, name, &model, ENOENT))
		return ENOENT;
	if (fd_msg_search_avp(msg, model, &avp) || !avp)
		return ENOENT;
	if (fd_msg_avp_hdr(avp, &hdr) || !hdr->avp_value)
		return ENOENT;

	snprintf(buf, blen, "%.*s", (int)hdr->avp_value->os.len, (char *)hdr->avp_value->os.data);
	(void)code;
	return 0;
}

static int crit_value_matches(struct route_rule *rule, const char *value)
{
	size_t len;

	if (rule->crit == ROUTE_CRI_ALL)
		return 1;
	if (!value || !*value)
		return 0;

	len = strlen(value);
	if (!rule->crit_regex) {
		size_t clen = strlen(rule->crit_val);
		return (len == clen) && !strncasecmp(value, rule->crit_val, len);
	}

#ifdef HAVE_REG_STARTEND
	{
		regmatch_t pmatch[1];
		memset(pmatch, 0, sizeof(pmatch));
		pmatch[0].rm_so = 0;
		pmatch[0].rm_eo = (regoff_t)len;
		return regexec(&rule->crit_preg, value, 0, pmatch, REG_STARTEND) == 0;
	}
#else
	{
		char *copy;
		int ret;
		CHECK_MALLOC(copy = os0dup((uint8_t *)value, len));
		ret = regexec(&rule->crit_preg, copy, 0, NULL, 0) == 0;
		free(copy);
		return ret;
	}
#endif
}

static struct rtd_candidate *route_pick_winner(struct fd_list *candidates)
{
	struct fd_list *li;
	struct rtd_candidate *best = NULL;

	for (li = candidates->next; li != candidates; li = li->next) {
		struct rtd_candidate *c = (struct rtd_candidate *)li;
		if (c->score < 0)
			continue;
		if (!best || c->score > best->score)
			best = c;
	}
	return best;
}

static void route_stats_incr(struct route_rule *rule, int routed)
{
	struct route_stats_row *row = NULL;
	char key[KEYLEN];

	snprintf(key, sizeof(key), "%s|%s|%s", rule->label, rule->crit_desc,
			rule->target[0] ? rule->target : "*");

	CHECK_POSIX(pthread_rwlock_rdlock(&stats_lock));
	HASH_FIND_STR(route_stats_head, key, row);
	if (row) {
		row->match_count++;
		if (routed)
			row->routed_count++;
		CHECK_POSIX(pthread_rwlock_unlock(&stats_lock));
		return;
	}
	CHECK_POSIX(pthread_rwlock_unlock(&stats_lock));

	CHECK_POSIX(pthread_rwlock_wrlock(&stats_lock));
	HASH_FIND_STR(route_stats_head, key, row);
	if (!row) {
		CHECK_MALLOC_DO(row = calloc(1, sizeof(*row)), {
			pthread_rwlock_unlock(&stats_lock);
			return;
		});
		strncpy(row->key, key, sizeof(row->key) - 1);
		strncpy(row->label, rule->label, sizeof(row->label) - 1);
		strncpy(row->crit_desc, rule->crit_desc, sizeof(row->crit_desc) - 1);
		strncpy(row->target, rule->target[0] ? rule->target : "*", sizeof(row->target) - 1);
		HASH_ADD_STR(route_stats_head, key, row);
	}
	row->match_count++;
	if (routed)
		row->routed_count++;
	CHECK_POSIX(pthread_rwlock_unlock(&stats_lock));
}

static void route_stats_special(const char *label, const char *crit, const char *target, int routed)
{
	struct route_stats_row stub;

	memset(&stub, 0, sizeof(stub));
	snprintf(stub.label, sizeof(stub.label), "%s", label);
	snprintf(stub.crit_desc, sizeof(stub.crit_desc), "%s", crit);
	snprintf(stub.target, sizeof(stub.target), "%s", target);
	route_stats_incr(&stub, routed);
}

static void route_stats_eval(struct msg *msg, struct fd_list *candidates)
{
	struct fd_list *li;
	char avpbuf[REALMLEN];
	struct rtd_candidate *winner;
	int any_match = 0;

	if (FD_IS_LIST_EMPTY(&route_rules) || FD_IS_LIST_EMPTY(candidates))
		return;

	winner = route_pick_winner(candidates);

	for (li = route_rules.next; li != &route_rules; li = li->next) {
		struct route_rule *rule = (struct route_rule *)li;
		int routed = 0;

		if (rule->crit != ROUTE_CRI_ALL) {
			if (msg_get_avp_str(msg, rule->crit, avpbuf, sizeof(avpbuf)) != 0)
				continue;
			if (!crit_value_matches(rule, avpbuf))
				continue;
		}

		any_match = 1;

		if (winner && rule->target[0]) {
			if (fd_os_almostcasesrch((uint8_t *)winner->diamid, winner->diamidlen,
					(uint8_t *)rule->target, strlen(rule->target), NULL) == 0)
				routed = 1;
		} else if (winner) {
			routed = 1;
		}

		route_stats_incr(rule, routed);
	}

	if (!any_match)
		route_stats_special("(unmatched)", "no rule matched", "-", 0);

	if (!winner)
		route_stats_special("(no peer)", "all scores < 0", "-", 0);
}

static int route_rt_out_cb(void *cbdata, struct msg **pmsg, struct fd_list *candidates)
{
	struct msg_hdr *hdr;

	(void)cbdata;
	if (!pmsg || !*pmsg || !candidates)
		return 0;
	if (fd_msg_hdr(*pmsg, &hdr) != 0)
		return 0;
	if (!(hdr->msg_flags & CMD_FLAG_REQUEST))
		return 0;

	route_stats_eval(*pmsg, candidates);
	return 0;
}

static int conf_load(char *conffile)
{
	FILE *f;
	char line[512];
	char *path = conffile;

	TRACE_ENTRY("%p", conffile);
	if (!path || !*path)
		path = "/etc/freeDiameter/dra_rtstats.conf";

	f = fopen(path, "r");
	if (!f) {
		fd_log_notice("%s: no config file '%s', using defaults (port %u)", MODULE_NAME, path, (unsigned)DEFAULT_PORT);
		return 0;
	}

	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		char *key, *val, *val2;
		while (*p && isspace((unsigned char)*p))
			p++;
		if (!*p || *p == '#')
			continue;
		key = p;
		while (*p && *p != '=' && !isspace((unsigned char)*p))
			p++;
		while (*p && isspace((unsigned char)*p))
			p++;
		if (*p != '=')
			continue;
		*p++ = '\0';
		{
			char *e = key + strlen(key);
			while (e > key && isspace((unsigned char)e[-1]))
				*--e = '\0';
		}
		while (*p && isspace((unsigned char)*p))
			p++;
		val = p;
		while (*p && *p != ';' && *p != '\n' && *p != '#')
			p++;
		if (*p)
			*p++ = '\0';
		/* trim trailing space on val */
		{
			char *e = val + strlen(val);
			while (e > val && isspace((unsigned char)e[-1]))
				*--e = '\0';
		}

		if (!strcasecmp(key, "Port")) {
			unsigned long prt = strtoul(val, NULL, 10);
			if (prt > 0 && prt < 65536)
				http_port = (uint16_t)prt;
		} else if (!strcasecmp(key, "realm_label")) {
			val2 = strchr(val, ':');
			if (val2) {
				char *a = val, *b = val2 + 1;
				*val2 = '\0';
				while (*b && isspace((unsigned char)*b))
					b++;
				if (*a && *b)
					CHECK_FCT(add_label(&realm_labels, a, b));
			}
		} else if (!strcasecmp(key, "peer_label")) {
			val2 = strchr(val, ':');
			if (val2) {
				char *a = val, *b = val2 + 1;
				*val2 = '\0';
				while (*b && isspace((unsigned char)*b))
					b++;
				if (*a && *b)
					CHECK_FCT(add_label(&peer_labels, a, b));
			}
		} else if (!strcasecmp(key, "route_match")) {
			if (route_match_parse_line(val) != 0)
				fd_log_error("%s: invalid route_match line: %s", MODULE_NAME, val);
		} else if (!strcasecmp(key, "dh_replace")) {
			val2 = strchr(val, ':');
			if (val2) {
				char *a = val, *b = val2 + 1;
				*val2 = '\0';
				if (dh_replace_add(a, b) != 0)
					fd_log_error("%s: invalid dh_replace line: %s", MODULE_NAME, val);
			}
		}
	}
	fclose(f);
	fd_log_notice("%s: loaded config from '%s', HTTP port %u", MODULE_NAME, path, (unsigned)http_port);
	return 0;
}

static void avp_find_realms(struct msg *msg, char *orealm, size_t olen, char *drealm, size_t dlen)
{
	struct avp *avp = NULL;

	orealm[0] = drealm[0] = '\0';
	CHECK_FCT_DO(fd_msg_browse(msg, MSG_BRW_FIRST_CHILD, &avp, NULL), return);
	while (avp) {
		struct avp_hdr *hdr;
		CHECK_FCT_DO(fd_msg_avp_hdr(avp, &hdr), break);
		if (!(hdr->avp_flags & AVP_FLAG_VENDOR) && hdr->avp_value) {
			if (hdr->avp_code == AC_ORIGIN_REALM && !orealm[0]) {
				snprintf(orealm, olen, "%.*s", (int)hdr->avp_value->os.len, (char *)hdr->avp_value->os.data);
			} else if (hdr->avp_code == AC_DESTINATION_REALM && !drealm[0]) {
				snprintf(drealm, dlen, "%.*s", (int)hdr->avp_value->os.len, (char *)hdr->avp_value->os.data);
			}
		}
		if (orealm[0] && drealm[0])
			break;
		CHECK_FCT_DO(fd_msg_browse(avp, MSG_BRW_NEXT, &avp, NULL), break);
	}
}

#define S6A_APPLICATION_ID 16777251

static const char *s6a_short_name(command_code_t code, int is_req)
{
	switch (code) {
	case 316: return is_req ? "ULR" : "ULA";
	case 317: return is_req ? "CLR" : "CLA";
	case 318: return is_req ? "AIR" : "AIA";
	case 319: return is_req ? "IDR" : "IDA";
	case 320: return is_req ? "DSR" : "DSA";
	case 321: return is_req ? "PUR" : "PUA";
	case 322: return is_req ? "RSR" : "RSA";
	case 323: return is_req ? "NFR" : "NFA";
	case 324: return is_req ? "ECR" : "ECA";
	default: return NULL;
	}
}

static const char *cmd_name_from_hdr(struct msg_hdr *hdr)
{
	static char buf[CMDLEN];
	struct dict_object *obj = NULL;
	struct dict_cmd_data cmd_data;
	command_code_t code = hdr->msg_code;
	int is_req = (hdr->msg_flags & CMD_FLAG_REQUEST) != 0;
	int ret;

	if (!fd_g_config || !fd_g_config->cnf_dict)
		goto fallback;

	ret = fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND,
			is_req ? CMD_BY_CODE_R : CMD_BY_CODE_A, &code, &obj, ENOENT);
	if (!ret && obj) {
		ret = fd_dict_getval(obj, &cmd_data);
		if (!ret && cmd_data.cmd_name) {
			/* Use short name: last component or abbreviate common S6a */
			const char *n = cmd_data.cmd_name;
			if (!strncmp(n, "Authentication-Information-", 29))
				return is_req ? "AIR" : "AIA";
			if (!strncmp(n, "Update-Location-", 16))
				return is_req ? "ULR" : "ULA";
			if (!strncmp(n, "Cancel-Location-", 16))
				return is_req ? "CLR" : "CLA";
			if (!strncmp(n, "Purge-UE-", 9))
				return is_req ? "PUR" : "PUA";
			if (!strncmp(n, "Insert-Subscriber-Data-", 23))
				return is_req ? "IDR" : "IDA";
			if (!strncmp(n, "Delete-Subscriber-Data-", 23))
				return is_req ? "DSR" : "DSA";
			snprintf(buf, sizeof(buf), "%.47s", n);
			return buf;
		}
	}

	if (hdr->msg_appl == S6A_APPLICATION_ID) {
		const char *s6a = s6a_short_name(hdr->msg_code, is_req);
		if (s6a)
			return s6a;
	}

fallback:
	snprintf(buf, sizeof(buf), "%s%u", is_req ? "REQ-" : "ANS-", (unsigned)hdr->msg_code);
	return buf;
}

static int peer_is_up(int st)
{
	return st == STATE_OPEN || st == STATE_REOPEN || st == STATE_CLOSING_GRACE;
}

static void peer_link_name(const char *peer_id, char *link, size_t llen)
{
	const char *lk = lookup_label(&peer_labels, peer_id);
	if (!lk)
		lk = peer_id && *peer_id ? peer_id : "-";
	snprintf(link, llen, "%s", lk);
}

static void stats_incr(const char *dir, const char *peer_id,
		const char *orealm, const char *drealm, const char *cmd,
		const char *msg_code)
{
	struct stats_row *row = NULL;
	char oper[LABELLEN];
	char link[LABELLEN];
	char key[KEYLEN];
	const char *op_label;

	op_label = lookup_label(&realm_labels, orealm);
	if (!op_label)
		op_label = orealm && *orealm ? orealm : "-";
	snprintf(oper, sizeof(oper), "%s", op_label);

	peer_link_name(peer_id, link, sizeof(link));

	snprintf(key, sizeof(key), "%s|%s|%s|%s|%s|%s|%s|%s",
			dir, oper, link, peer_id ? peer_id : "-",
			orealm && *orealm ? orealm : "-",
			drealm && *drealm ? drealm : "-", cmd,
			msg_code && *msg_code ? msg_code : "-");

	CHECK_POSIX(pthread_rwlock_rdlock(&stats_lock));
	HASH_FIND_STR(stats_head, key, row);
	if (row) {
		row->count++;
		CHECK_POSIX(pthread_rwlock_unlock(&stats_lock));
		return;
	}
	CHECK_POSIX(pthread_rwlock_unlock(&stats_lock));

	CHECK_POSIX(pthread_rwlock_wrlock(&stats_lock));
	HASH_FIND_STR(stats_head, key, row);
	if (!row) {
		CHECK_MALLOC_DO(row = calloc(1, sizeof(*row)), { pthread_rwlock_unlock(&stats_lock); return; });
		strncpy(row->key, key, sizeof(row->key) - 1);
		strncpy(row->dir, dir, sizeof(row->dir) - 1);
		strncpy(row->oper, oper, sizeof(row->oper) - 1);
		strncpy(row->link, link, sizeof(row->link) - 1);
		strncpy(row->peer, peer_id ? peer_id : "-", sizeof(row->peer) - 1);
		strncpy(row->orealm, orealm && *orealm ? orealm : "-", sizeof(row->orealm) - 1);
		strncpy(row->drealm, drealm && *drealm ? drealm : "-", sizeof(row->drealm) - 1);
		strncpy(row->cmd, cmd, sizeof(row->cmd) - 1);
		strncpy(row->msg_code, msg_code && *msg_code ? msg_code : "-", sizeof(row->msg_code) - 1);
		HASH_ADD_STR(stats_head, key, row);
	}
	row->count++;
	CHECK_POSIX(pthread_rwlock_unlock(&stats_lock));
}

static void stats_record(enum fd_hook_type type, struct msg *msg, struct peer_hdr *peer)
{
	struct msg_hdr *hdr;
	char orealm[REALMLEN];
	char drealm[REALMLEN];
	const char *cmd;
	char msg_code[CODELEN];
	const char *dir;
	const char *peer_id;

	if (!msg || !peer)
		return;

	CHECK_FCT_DO(fd_msg_hdr(msg, &hdr), return);
	avp_find_realms(msg, orealm, sizeof(orealm), drealm, sizeof(drealm));
	cmd = cmd_name_from_hdr(hdr);
	snprintf(msg_code, sizeof(msg_code), "%u", (unsigned)hdr->msg_code);
	peer_id = peer->info.pi_diamid;

	if (type == HOOK_MESSAGE_RECEIVED)
		dir = "in";
	else if (type == HOOK_MESSAGE_SENT)
		dir = "out";
	else
		return;

	stats_incr(dir, peer_id, orealm, drealm, cmd, msg_code);
}

static void stats_hook_cb(enum fd_hook_type type, struct msg *msg, struct peer_hdr *peer,
		void *other, struct fd_hook_permsgdata *pmd, void *regdata)
{
	(void)other;
	(void)pmd;
	(void)regdata;
	if (type == HOOK_MESSAGE_RECEIVED || type == HOOK_MESSAGE_SENT)
		stats_record(type, msg, peer);
}

static int stats_rows_cmp(const void *a, const void *b)
{
	const struct stats_snap * const *ra = a;
	const struct stats_snap * const *rb = b;
	if ((*rb)->count > (*ra)->count)
		return 1;
	if ((*rb)->count < (*ra)->count)
		return -1;
	return strcmp((*ra)->peer, (*rb)->peer);
}

static int link_peer_cmp(const void *a, const void *b)
{
	const struct link_peer_snap *pa = a;
	const struct link_peer_snap *pb = b;
	int c = strcmp(pa->link, pb->link);
	if (c != 0)
		return c;
	return strcmp(pa->peer, pb->peer);
}

static struct link_peer_snap *link_peer_get(struct link_peer_snap **arr, size_t *n, size_t *cap,
		const char *peer_id, int up)
{
	size_t i;
	struct link_peer_snap *p;

	for (i = 0; i < *n; i++) {
		if (!strcmp((*arr)[i].peer, peer_id)) {
			if (up >= 0)
				(*arr)[i].up = up;
			return &(*arr)[i];
		}
	}
	if (*n >= *cap) {
		size_t nc = *cap ? *cap * 2 : 16;
		struct link_peer_snap *na = realloc(*arr, nc * sizeof(**arr));
		if (!na)
			return NULL;
		*arr = na;
		*cap = nc;
	}
	p = &(*arr)[*n];
	memset(p, 0, sizeof(*p));
	snprintf(p->peer, sizeof(p->peer), "%s", peer_id);
	peer_link_name(peer_id, p->link, sizeof(p->link));
	if (up >= 0)
		p->up = up;
	(*n)++;
	return p;
}

static struct link_realm_snap *link_realm_add(struct link_realm_snap **arr, size_t *n, size_t *cap,
		const char *dir, const char *orealm, const char *drealm, uint64_t add)
{
	size_t i;
	struct link_realm_snap *r;

	for (i = 0; i < *n; i++) {
		r = &(*arr)[i];
		if (!strcmp(r->dir, dir) && !strcmp(r->orealm, orealm) && !strcmp(r->drealm, drealm)) {
			r->count += add;
			return r;
		}
	}
	if (*n >= *cap) {
		size_t nc = *cap ? *cap * 2 : 8;
		struct link_realm_snap *na = realloc(*arr, nc * sizeof(**arr));
		if (!na)
			return NULL;
		*arr = na;
		*cap = nc;
	}
	r = &(*arr)[*n];
	memset(r, 0, sizeof(*r));
	snprintf(r->dir, sizeof(r->dir), "%s", dir);
	snprintf(r->orealm, sizeof(r->orealm), "%s", orealm);
	snprintf(r->drealm, sizeof(r->drealm), "%s", drealm);
	r->count = add;
	(*n)++;
	return r;
}

static struct link_msg_snap *link_msg_add(struct link_msg_snap **arr, size_t *n, size_t *cap,
		const char *dir, const char *cmd, const char *msg_code, uint64_t add)
{
	size_t i;
	struct link_msg_snap *m;

	for (i = 0; i < *n; i++) {
		m = &(*arr)[i];
		if (!strcmp(m->dir, dir) && !strcmp(m->cmd, cmd) && !strcmp(m->msg_code, msg_code)) {
			m->count += add;
			return m;
		}
	}
	if (*n >= *cap) {
		size_t nc = *cap ? *cap * 2 : 8;
		struct link_msg_snap *na = realloc(*arr, nc * sizeof(**arr));
		if (!na)
			return NULL;
		*arr = na;
		*cap = nc;
	}
	m = &(*arr)[*n];
	memset(m, 0, sizeof(*m));
	snprintf(m->dir, sizeof(m->dir), "%s", dir);
	snprintf(m->cmd, sizeof(m->cmd), "%s", cmd);
	snprintf(m->msg_code, sizeof(m->msg_code), "%s", msg_code);
	m->count = add;
	(*n)++;
	return m;
}

static int link_realm_cmp(const void *a, const void *b)
{
	const struct link_realm_snap *ra = a;
	const struct link_realm_snap *rb = b;
	if (rb->count > ra->count)
		return 1;
	if (rb->count < ra->count)
		return -1;
	return 0;
}

static int link_msg_cmp(const void *a, const void *b)
{
	const struct link_msg_snap *ma = a;
	const struct link_msg_snap *mb = b;
	if (mb->count > ma->count)
		return 1;
	if (mb->count < ma->count)
		return -1;
	return strcmp(ma->cmd, mb->cmd);
}

static struct global_msg_snap *global_msg_get(struct global_msg_snap **arr, size_t *n, size_t *cap,
		const char *cmd, const char *msg_code)
{
	size_t i;
	struct global_msg_snap *g;

	for (i = 0; i < *n; i++) {
		g = &(*arr)[i];
		if (!strcmp(g->cmd, cmd) && !strcmp(g->msg_code, msg_code))
			return g;
	}
	if (*n >= *cap) {
		size_t nc = *cap ? *cap * 2 : 16;
		struct global_msg_snap *na = realloc(*arr, nc * sizeof(**arr));
		if (!na)
			return NULL;
		*arr = na;
		*cap = nc;
	}
	g = &(*arr)[*n];
	memset(g, 0, sizeof(*g));
	snprintf(g->cmd, sizeof(g->cmd), "%s", cmd);
	snprintf(g->msg_code, sizeof(g->msg_code), "%s", msg_code);
	(*n)++;
	return g;
}

static void global_msg_add(struct global_msg_snap **arr, size_t *n, size_t *cap,
		const char *dir, const char *cmd, const char *msg_code, uint64_t add)
{
	struct global_msg_snap *g = global_msg_get(arr, n, cap, cmd, msg_code);
	if (!g)
		return;
	if (!strcmp(dir, "in"))
		g->in_cnt += add;
	else if (!strcmp(dir, "out"))
		g->out_cnt += add;
}

static int global_msg_cmp(const void *a, const void *b)
{
	const struct global_msg_snap *ga = a;
	const struct global_msg_snap *gb = b;
	uint64_t ta = ga->in_cnt + ga->out_cnt;
	uint64_t tb = gb->in_cnt + gb->out_cnt;
	if (tb > ta)
		return 1;
	if (tb < ta)
		return -1;
	return strcmp(ga->cmd, gb->cmd);
}

static size_t render_html(char **out, size_t *outlen)
{
	struct stats_row *row, *tmp;
	struct route_stats_row *rrow, *rtmp;
	struct stats_snap *snap = NULL;
	struct route_stats_snap *rsnap = NULL;
	struct stats_snap **sorted = NULL;
	struct route_stats_snap **rsorted = NULL;
	struct link_peer_snap *links = NULL;
	size_t n = 0, rn = 0, ln = 0, ln_cap = 0, i, j, off = 0;
	char *buf = NULL;
	size_t blen = 0;
	const char *hdr =
		"<!DOCTYPE html><html><head><meta charset=utf-8>"
		"<title>DRA relay statistics</title>"
		"<style>body{font-family:sans-serif}table{border-collapse:collapse;width:100%%}"
		"th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}"
		"th{background:#eee}tr:nth-child(even){background:#f9f9f9}"
		"h2{margin-top:2em}h3{margin-top:1em;font-size:1.05em}"
		".up{color:#060;font-weight:bold}.down{color:#c00;font-weight:bold}"
		".unmatch{background:#fff3f3}.linkbox{border:1px solid #ddd;margin:1.5em 0;padding:0.5em 1em}"
		"</style></head><body>"
		"<h1>DRA relay statistics</h1>"
		"<p><a href=\"/\">reload</a> | <a href=\"/reset\">reset counters</a></p>"
		"<h2>Links overview</h2>"
		"<table><tr><th>Link</th><th>Peer</th><th>State</th>"
		"<th>Received (in)</th><th>Sent (out)</th><th>Total</th></tr>";
	const char *route_hdr =
		"<h2>Route match report</h2>"
		"<p>Evaluated on outbound relay requests after rt_default / realm scoring. "
		"<em>Matches</em> = criteria matched; <em>Routed</em> = winning peer equals target. "
		"Rows <span style=\"background:#fff3f3\">(unmatched)</span> / "
		"<span style=\"background:#fff3f3\">(no peer)</span> are automatic catch-alls.</p>"
		"<table><tr><th>Route</th><th>Criteria</th><th>Target peer</th>"
		"<th>Matches</th><th>Routed</th><th>Match rate</th></tr>";

	CHECK_POSIX(pthread_rwlock_rdlock(&stats_lock));
	HASH_ITER(hh, stats_head, row, tmp)
		n++;
	HASH_ITER(hh, route_stats_head, rrow, rtmp)
		rn++;
	if (n) {
		CHECK_MALLOC_DO(snap = calloc(n, sizeof(*snap)), n = 0);
		CHECK_MALLOC_DO(sorted = calloc(n, sizeof(*sorted)), { free(snap); snap = NULL; n = 0; });
		i = 0;
		HASH_ITER(hh, stats_head, row, tmp) {
			struct stats_snap *s = &snap[i];
			struct link_peer_snap *lp;
			strncpy(s->dir, row->dir, sizeof(s->dir) - 1);
			strncpy(s->oper, row->oper, sizeof(s->oper) - 1);
			strncpy(s->link, row->link, sizeof(s->link) - 1);
			strncpy(s->peer, row->peer, sizeof(s->peer) - 1);
			strncpy(s->orealm, row->orealm, sizeof(s->orealm) - 1);
			strncpy(s->drealm, row->drealm, sizeof(s->drealm) - 1);
			strncpy(s->cmd, row->cmd, sizeof(s->cmd) - 1);
			strncpy(s->msg_code, row->msg_code, sizeof(s->msg_code) - 1);
			s->count = row->count;
			sorted[i++] = s;
			lp = link_peer_get(&links, &ln, &ln_cap, s->peer, -1);
			if (lp) {
				if (!strcmp(s->dir, "in"))
					lp->in_cnt += s->count;
				else if (!strcmp(s->dir, "out"))
					lp->out_cnt += s->count;
			}
		}
		qsort(sorted, n, sizeof(*sorted), stats_rows_cmp);
	}
	if (rn) {
		CHECK_MALLOC_DO(rsnap = calloc(rn, sizeof(*rsnap)), rn = 0);
		CHECK_MALLOC_DO(rsorted = calloc(rn, sizeof(*rsorted)), { free(rsnap); rsnap = NULL; rn = 0; });
		i = 0;
		HASH_ITER(hh, route_stats_head, rrow, rtmp) {
			struct route_stats_snap *s = &rsnap[i];
			strncpy(s->label, rrow->label, sizeof(s->label) - 1);
			strncpy(s->crit_desc, rrow->crit_desc, sizeof(s->crit_desc) - 1);
			strncpy(s->target, rrow->target, sizeof(s->target) - 1);
			s->match_count = rrow->match_count;
			s->routed_count = rrow->routed_count;
			rsorted[i++] = s;
		}
	}
	CHECK_POSIX(pthread_rwlock_unlock(&stats_lock));

	{
		struct fd_list *li;
		CHECK_POSIX(pthread_rwlock_rdlock(&fd_g_peers_rw));
		for (li = fd_g_peers.next; li != &fd_g_peers; li = li->next) {
			struct peer_hdr *ph = (struct peer_hdr *)li;
			link_peer_get(&links, &ln, &ln_cap, ph->info.pi_diamid,
					peer_is_up(fd_peer_get_state(ph)) ? 1 : 0);
		}
		CHECK_POSIX(pthread_rwlock_unlock(&fd_g_peers_rw));
	}
	if (ln)
		qsort(links, ln, sizeof(*links), link_peer_cmp);

#define APPEND(fmt, ...) do { \
		int need = snprintf(NULL, 0, fmt, ##__VA_ARGS__); \
		if (need < 0) break; \
		if (off + (size_t)need + 1 > blen) { \
			size_t nblen = blen ? blen * 2 : 65536; \
			char *nb = realloc(buf, nblen); \
			if (!nb) break; \
			buf = nb; blen = nblen; \
		} \
		off += snprintf(buf + off, blen - off, fmt, ##__VA_ARGS__); \
	} while (0)

	CHECK_MALLOC(buf = malloc(262144));
	blen = 262144;
	off = 0;
	APPEND("%s", hdr);
	for (i = 0; i < ln; i++) {
		struct link_peer_snap *lp = &links[i];
		APPEND("<tr><td>%s</td><td><small>%s</small></td><td class=\"%s\">%s</td>"
		       "<td>%llu</td><td>%llu</td><td>%llu</td></tr>",
		       lp->link, lp->peer, lp->up ? "up" : "down", lp->up ? "UP" : "DOWN",
		       (unsigned long long)lp->in_cnt, (unsigned long long)lp->out_cnt,
		       (unsigned long long)(lp->in_cnt + lp->out_cnt));
	}
	APPEND("</table>");

	{
		struct global_msg_snap *gmsgs = NULL;
		size_t gn = 0, gn_cap = 0;

		for (j = 0; j < n; j++)
			global_msg_add(&gmsgs, &gn, &gn_cap, sorted[j]->dir,
					sorted[j]->cmd, sorted[j]->msg_code, sorted[j]->count);
		if (gn)
			qsort(gmsgs, gn, sizeof(*gmsgs), global_msg_cmp);

		APPEND("<h2>Message counters (AIR, AIA, ULR, …)</h2>"
		       "<p>Totals across all links since last reset.</p>"
		       "<table><tr><th>Message</th><th>Code</th><th>Received (in)</th>"
		       "<th>Sent (out)</th><th>Total</th></tr>");
		if (!gn)
			APPEND("<tr><td colspan=5><em>No traffic yet</em></td></tr>");
		for (j = 0; j < gn; j++)
			APPEND("<tr><td><strong>%s</strong></td><td>%s</td><td>%llu</td>"
			       "<td>%llu</td><td>%llu</td></tr>",
			       gmsgs[j].cmd, gmsgs[j].msg_code,
			       (unsigned long long)gmsgs[j].in_cnt,
			       (unsigned long long)gmsgs[j].out_cnt,
			       (unsigned long long)(gmsgs[j].in_cnt + gmsgs[j].out_cnt));
		APPEND("</table>");
		free(gmsgs);
	}

	APPEND("<h2>Per-link detail</h2>");

	for (i = 0; i < ln; i++) {
		struct link_peer_snap *lp = &links[i];
		struct link_realm_snap *realms = NULL;
		struct link_msg_snap *msgs = NULL;
		size_t rn2 = 0, rn_cap = 0, mn = 0, mn_cap = 0;

		for (j = 0; j < n; j++) {
			struct stats_snap *s = sorted[j];
			if (strcmp(s->peer, lp->peer))
				continue;
			link_realm_add(&realms, &rn2, &rn_cap, s->dir, s->orealm, s->drealm, s->count);
			link_msg_add(&msgs, &mn, &mn_cap, s->dir, s->cmd, s->msg_code, s->count);
		}
		if (rn2)
			qsort(realms, rn2, sizeof(*realms), link_realm_cmp);
		if (mn)
			qsort(msgs, mn, sizeof(*msgs), link_msg_cmp);

		APPEND("<div class=\"linkbox\"><h3>%s <span class=\"%s\">%s</span></h3>"
		       "<p><small>%s</small></p>",
		       lp->link, lp->up ? "up" : "down", lp->up ? "UP" : "DOWN", lp->peer);

		APPEND("<h4>Realms (received / sent)</h4>"
		       "<table><tr><th>Dir</th><th>Origin-Realm</th><th>Dest-Realm</th><th>Count</th></tr>");
		if (!rn2)
			APPEND("<tr><td colspan=4><em>No traffic yet</em></td></tr>");
		for (j = 0; j < rn2; j++)
			APPEND("<tr><td>%s</td><td>%s</td><td>%s</td><td>%llu</td></tr>",
			       realms[j].dir, realms[j].orealm, realms[j].drealm,
			       (unsigned long long)realms[j].count);
		APPEND("</table>");

		APPEND("<h4>Messages (AIR, AIA, …)</h4>"
		       "<table><tr><th>Dir</th><th>Message</th><th>Count</th></tr>");
		if (!mn)
			APPEND("<tr><td colspan=3><em>No traffic yet</em></td></tr>");
		for (j = 0; j < mn; j++)
			APPEND("<tr><td>%s</td><td>%s</td><td>%llu</td></tr>",
			       msgs[j].dir, msgs[j].cmd, (unsigned long long)msgs[j].count);
		APPEND("</table>");

		APPEND("<h4>Commands (Diameter code)</h4>"
		       "<table><tr><th>Dir</th><th>Code</th><th>Message</th><th>Count</th></tr>");
		if (!mn)
			APPEND("<tr><td colspan=4><em>No traffic yet</em></td></tr>");
		for (j = 0; j < mn; j++)
			APPEND("<tr><td>%s</td><td>%s</td><td>%s</td><td>%llu</td></tr>",
			       msgs[j].dir, msgs[j].msg_code, msgs[j].cmd,
			       (unsigned long long)msgs[j].count);
		APPEND("</table></div>");

		free(realms);
		free(msgs);
	}

	APPEND("%s", route_hdr);
	if (rn == 0) {
		APPEND("<tr><td colspan=6><em>No route_match rules configured in dra_rtstats.conf</em></td></tr>");
	}
	for (i = 0; i < rn; i++) {
		struct route_stats_snap *s = rsorted[i];
		double rate = s->match_count ? (100.0 * (double)s->routed_count / (double)s->match_count) : 0.0;
		const char *rowclass = (!strncmp(s->label, "(unmatched)", 11) ||
				!strncmp(s->label, "(no peer)", 9)) ? " class=\"unmatch\"" : "";
		APPEND("<tr%s><td>%s</td><td><code>%s</code></td><td>%s</td>"
		       "<td>%llu</td><td>%llu</td><td>%.1f%%</td></tr>",
		       rowclass, s->label, s->crit_desc, s->target,
		       (unsigned long long)s->match_count,
		       (unsigned long long)s->routed_count, rate);
	}
	APPEND("</table><p><small>dra_rtstats — in=received on peer, out=sent to peer</small></p></body></html>");

	free(snap);
	free(sorted);
	free(rsnap);
	free(rsorted);
	free(links);
	*out = buf;
	*outlen = off;
	return 0;
}

static void stats_reset(void)
{
	struct stats_row *row, *tmp;
	struct route_stats_row *rrow, *rtmp;
	CHECK_POSIX_DO(pthread_rwlock_wrlock(&stats_lock), return);
	HASH_ITER(hh, stats_head, row, tmp) {
		HASH_DEL(stats_head, row);
		free(row);
	}
	stats_head = NULL;
	HASH_ITER(hh, route_stats_head, rrow, rtmp) {
		HASH_DEL(route_stats_head, rrow);
		free(rrow);
	}
	route_stats_head = NULL;
	CHECK_POSIX_DO(pthread_rwlock_unlock(&stats_lock), return);
}

static void http_serve_client(int cli)
{
	char req[1024];
	ssize_t n;
	char *body = NULL;
	size_t blen = 0;
	const char *resp;
	char hdr[256];

	n = recv(cli, req, sizeof(req) - 1, 0);
	if (n <= 0) {
		close(cli);
		return;
	}
	req[n] = '\0';

	if (strstr(req, "GET /reset")) {
		stats_reset();
		resp = "HTTP/1.0 302 Found\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
		send(cli, resp, strlen(resp), 0);
		close(cli);
		return;
	}

	render_html(&body, &blen);
	snprintf(hdr, sizeof(hdr),
		 "HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
		 "Cache-Control: no-store\r\n"
		 "Content-Length: %zu\r\nConnection: close\r\n\r\n", blen);
	send(cli, hdr, strlen(hdr), 0);
	if (body && blen)
		send(cli, body, blen, 0);
	free(body);
	close(cli);
}

static void *http_thread(void *arg)
{
	(void)arg;
	fd_log_threadname("dra_rtstats-http");

	while (http_run) {
		struct sockaddr_in cli_addr;
		socklen_t clen = sizeof(cli_addr);
		int cli = accept(http_sock, (struct sockaddr *)&cli_addr, &clen);
		if (cli < 0) {
			if (http_run)
				fd_log_error("%s: HTTP accept failed: %s", MODULE_NAME, strerror(errno));
			continue;
		}
		http_serve_client(cli);
	}
	return NULL;
}

static int http_start(void)
{
	struct sockaddr_in sin;
	int on = 1;

	http_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (http_sock < 0)
		return errno;

	setsockopt(http_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(http_port);

	if (bind(http_sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		close(http_sock);
		http_sock = -1;
		return errno;
	}
	if (listen(http_sock, 8) < 0) {
		close(http_sock);
		http_sock = -1;
		return errno;
	}

	http_run = 1;
	CHECK_POSIX(pthread_create(&http_thr, NULL, http_thread, NULL));
	fd_log_notice("%s: statistics HTTP UI on port %u (GET /)", MODULE_NAME, (unsigned)http_port);
	return 0;
}

static void http_stop(void)
{
	http_run = 0;
	if (http_sock >= 0) {
		close(http_sock);
		http_sock = -1;
	}
	if (http_thr) {
		pthread_cancel(http_thr);
		pthread_join(http_thr, NULL);
	}
}

static int dra_rtstats_main(char *conffile)
{
	TRACE_ENTRY("%p", conffile);

	CHECK_FCT(conf_load(conffile));
	CHECK_FCT(http_start());

	CHECK_FCT(fd_hook_register(HOOK_MASK(HOOK_MESSAGE_RECEIVED, HOOK_MESSAGE_SENT),
			stats_hook_cb, NULL, NULL, &stats_hdl));

	if (!FD_IS_LIST_EMPTY(&dh_replace_list)) {
		CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
				"Destination-Host", &dh_avp_model, ENOENT));
		CHECK_FCT(fd_rt_fwd_register(dh_replace_fwd_cb, NULL, RT_FWD_REQ, &dh_replace_hdl));
	}

	/* Run after rt_default (prio 5) and destination scoring (prio 10) */
	CHECK_FCT(fd_rt_out_register(route_rt_out_cb, NULL, -1, &route_rt_hdl));

	fd_log_notice("%s: counting relay traffic (in=RCV from peer, out=SND to peer)", MODULE_NAME);
	return 0;
}

void fd_ext_fini(void)
{
	if (dh_replace_hdl) {
		fd_rt_fwd_unregister(dh_replace_hdl, NULL);
		dh_replace_hdl = NULL;
	}
	if (route_rt_hdl) {
		fd_rt_out_unregister(route_rt_hdl, NULL);
		route_rt_hdl = NULL;
	}
	if (stats_hdl) {
		fd_hook_unregister(stats_hdl);
		stats_hdl = NULL;
	}
	http_stop();
	stats_reset();
	route_rules_free();
	dh_replace_list_free();
	label_maps_free(&realm_labels);
	label_maps_free(&peer_labels);
}

EXTENSION_ENTRY("dra_rtstats", dra_rtstats_main);
