#define _XOPEN_SOURCE 500

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sysexits.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <libgen.h>

#include <confuse.h> /* simple config parser */
#include "libmilter/mfapi.h"

#define CONF		"/etc/date_milter.conf"

/* global variables */
#ifdef DEBUG
bool debug = false;
#endif

/* global variables from config file */
double max_ago;
double max_ahead;
char *err_header_str;
char *err_date_str;
cfg_bool_t rej_misformed;

sfsistat
xxfi_connect(ctx, hostname, hostaddr)
	 SMFICTX *ctx;
	 char *hostname;
	 _SOCK_ADDR *hostaddr;
{
	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
xxfi_helo(ctx, helohost)
	 SMFICTX *ctx;
	 char *helohost;
{
	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
xxfi_envfrom(ctx, argv)
	 SMFICTX *ctx;
	 char **argv;
{
	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
xxfi_envrcpt(ctx, argv)
	 SMFICTX *ctx;
	 char **argv;
{
	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
xxfi_header(ctx, headerf, headerv)
	 SMFICTX *ctx;
	 char *headerf;
	 char *headerv;
{
	struct tm tm_header;
	time_t t_header, t_now;
	double diff = 0;

	char *err_msg = NULL;
	char *err_code = "550";    /* RFC 2821 */
	char *err_xcode = "5.7.1"; /* RFC 1893 */
	sfsistat ret = SMFIS_CONTINUE;

#ifdef DEBUG
	char *status = "can't parse";
	char buf[33];
#endif

	/* only check date header  */
	if (strcmp(headerf, "Date") != 0)
		return SMFIS_CONTINUE;
	
	/* check date */
	memset (&tm_header, '\0', sizeof (tm_header));
	if (strptime(headerv, "%a, %d %b %Y %T %z", &tm_header) != 0)
	{
		tm_header.tm_isdst = -1; /* not set by strptime() */

		t_header = mktime(&tm_header);
		t_now = time(NULL);

		diff = difftime(t_now, t_header) / 3600; /* hours ago */

#ifdef DEBUG
		if (diff >= 0)
			snprintf(buf, sizeof(buf), "%.2fh ago", diff);
		else
			snprintf(buf, sizeof(buf), "%.2fh ahead", fabs(diff));

		status = buf;
#endif

		if ((diff >= max_ago) || 
			(fabs(diff) >= max_ahead))
		{
			err_msg = err_date_str;
			ret = SMFIS_REJECT;
		}
	}
	else if (rej_misformed == cfg_true)
	{
		err_msg = err_header_str;
		ret = SMFIS_REJECT;
	}

#ifdef DEBUG
	/* display */
	if (debug)
	{
		fprintf(stderr, "%s: %s -> %s\n", headerf, headerv, status);
		if (ret != SMFIS_CONTINUE)
			fprintf(stderr, "Msg : %s %s %s\n",
					err_code, err_xcode, err_msg);
	}
#endif

	/* continue processing */
	if (ret != SMFIS_CONTINUE)
		smfi_setreply(ctx, err_code, err_xcode, err_msg);
	return ret;
}

sfsistat
xxfi_eoh(ctx)
	 SMFICTX *ctx;
{
	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
xxfi_body(ctx, bodyp, bodylen)
	 SMFICTX *ctx;
	 unsigned char *bodyp;
	 size_t bodylen;
{
	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
xxfi_eom(ctx)
	 SMFICTX *ctx;
{
	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
xxfi_abort(ctx)
	 SMFICTX *ctx;
{
	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
xxfi_cleanup(ctx, ok)
	 SMFICTX *ctx;
	 bool ok;
{
	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
xxfi_close(ctx)
	 SMFICTX *ctx;
{
	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
xxfi_unknown(ctx, cmd)
	SMFICTX *ctx;
	char *cmd;
{
	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
xxfi_data(ctx)
	SMFICTX *ctx;
{
	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
xxfi_negotiate(ctx, f0, f1, f2, f3, pf0, pf1, pf2, pf3)
	SMFICTX *ctx;
	unsigned long f0;
	unsigned long f1;
	unsigned long f2;
	unsigned long f3;
	unsigned long *pf0;
	unsigned long *pf1;
	unsigned long *pf2;
	unsigned long *pf3;
{
	return SMFIS_ALL_OPTS;
}

struct smfiDesc smfilter =
{
	"date_milter",	/* filter name */
	SMFI_VERSION,	/* version code -- do not change */
	SMFIF_ADDHDRS|SMFIF_ADDRCPT,
			/* flags */
	xxfi_connect,	/* connection info filter */
	xxfi_helo,	/* SMTP HELO command filter */
	xxfi_envfrom,	/* envelope sender filter */
	xxfi_envrcpt,	/* envelope recipient filter */
	xxfi_header,	/* header filter */
	xxfi_eoh,	/* end of header */
	xxfi_body,	/* body block filter */
	xxfi_eom,	/* end of message */
	xxfi_abort,	/* message aborted */
	xxfi_close,	/* connection cleanup */
	xxfi_unknown,	/* unknown SMTP commands */
	xxfi_data,	/* DATA command */
	xxfi_negotiate	/* Once, at the start of each SMTP connection */
};

static void
usage(prog)
	char *prog;
{
	fprintf(stderr,
		"Usage: %s -p socket-addr [-t timeout] [-c config-file]",
		basename(prog));
#ifdef DEBUG
	fprintf(stderr, " [-d]\n\n");
#else
	fprintf(stderr, "\n\n");
#endif

	fprintf(stderr, "\t -p  {unix:|local:}<filename> - use a named pipe.\n");
	fprintf(stderr, "\t     inet:port{@hostname|@ip-address} - use an IPV4 socket.\n");
	fprintf(stderr, "\t     inet6:port{@hostname|@ip-address} - use an IPV6 socket.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "\t -t  The number of seconds to wait before timing out (> 0).\n");
	fprintf(stderr, "\t     Zero means no wait, not \"wait forever\".\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "\t -c  Use this configuration file instead of the default\n");
	fprintf(stderr, "\t     file \"%s\".\n", CONF);
	fprintf(stderr, "\n");
#ifdef DEBUG
	fprintf(stderr, "\t -d  Enable dubugging output to stderr.\n");
	fprintf(stderr, "\n");
#endif
}

int
read_config(file)
	 const char *file;
{
	/* libConfuse: http://www.nongnu.org/confuse */
	cfg_opt_t opts[] = {
		CFG_SIMPLE_FLOAT("max_ago", &max_ago),
		CFG_SIMPLE_FLOAT("max_ahead", &max_ahead),
		CFG_SIMPLE_STR("err_header_str", &err_header_str),
		CFG_SIMPLE_STR("err_date_str", &err_date_str),
		CFG_SIMPLE_BOOL("reject_misformed_header", &rej_misformed),
		CFG_END()
	};
	cfg_t *cfg;

	/* defaults */
	max_ago = 24 * 12; /* 12 days */
	max_ahead = 24;    /* 1 day */
	err_header_str = strdup("Your date header is misformed");
	err_date_str = strdup("Fix your system clock and try again");
	rej_misformed = cfg_true;

#ifdef DEBUG
	if (debug) fprintf(stderr, "using config file: %s\n", file);
#endif
	cfg = cfg_init(opts, CFGF_NONE);
	if ((cfg_parse(cfg, file)) == CFG_PARSE_ERROR) return MI_FAILURE;

#ifdef DEBUG
	if (debug)
	{
		fprintf(stderr, "opt: max_ago          = %.2f\n", max_ago);
		fprintf(stderr, "opt: max_ahead        = %.2f\n", max_ahead);
		fprintf(stderr, "opt: err_header_str   = %s\n", err_header_str);
		fprintf(stderr, "opt: err_date_str     = %s\n", err_date_str);
		fprintf(stderr, "opt: reject_misformed_header = %s\n",
				rej_misformed ? "true" : "false");
	}
#endif

	cfg_free(cfg);
	return MI_SUCCESS;
}

int
main(argc, argv)
	 int argc;
	 char **argv;
{
	bool setconn = false;
	bool setconf = false;
	int c;
	int t = 7210;
	extern char *optarg;
	char *conf = CONF;
#ifdef DEBUG
	const char *args = "p:t:hc:d";
#else
	const char *args = "p:t:hc:";
#endif
	/* Process command line options */
	while ((c = getopt(argc, argv, args)) != -1)
	{
		switch (c)
		{
		  case 'p':
			if (optarg == NULL || *optarg == '\0')
			{
				(void) fprintf(stderr, "Illegal conn: %s\n",
					       optarg);
				exit(EX_USAGE);
			}
			if (smfi_setconn(optarg) == MI_FAILURE)
			{
				(void) fprintf(stderr,
					       "smfi_setconn failed\n");
				exit(EX_SOFTWARE);
			}

			/*
			**  If we're using a local socket, make sure it
			**  doesn't already exist.  Don't ever run this
			**  code as root!!
			*/

			if (strncasecmp(optarg, "unix:", 5) == 0)
				unlink(optarg + 5);
			else if (strncasecmp(optarg, "local:", 6) == 0)
				unlink(optarg + 6);
			setconn = true;
			break;

		  case 't':
			if (optarg == NULL || *optarg == '\0')
			{
				(void) fprintf(stderr, "Illegal timeout: %s\n",
					       optarg);
				exit(EX_USAGE);
			}
			t = atoi(optarg);
			break;

		  case 'c':
		  	if (optarg == NULL || *optarg == '\0')
			{
				(void) fprintf(stderr, "Illegal file: %s\n",
						optarg);
				exit(EX_USAGE);
			}

			setconf = true;
			conf = optarg;
		  	break;

#ifdef DEBUG
		  case 'd':
		  	debug = true;
			break;
#endif

		  case 'h':
		  default:
			usage(argv[0]);
			exit(EX_USAGE);
		}
	}
#ifdef DEBUG
	if (debug) fprintf(stderr, "%s: debugging enabled\n\n",
			basename(argv[0]));
#endif
	/* check connection settings */
	if (!setconn)
	{
		fprintf(stderr, "%s: Missing required -p argument\n",
				basename(argv[0]));
		usage(argv[0]);
		exit(EX_USAGE);
	}

	/* set timeout */
	if (smfi_settimeout(t) == MI_FAILURE)
	{
		(void) fprintf(stderr, "%s: smfi_settimeout failed\n",
				basename(argv[0]));
		exit(EX_SOFTWARE);
	}
#ifdef DEBUG
	if (debug) fprintf(stderr, "timeout set: %dsek.\n", t);
#endif

	/* check configuration file */
	if (setconf)
	{
		struct stat buf;
		if (access(conf, F_OK) != 0 || access(conf, R_OK) != 0)
		{
			fprintf(stderr, "%s: Config file unreadable: %s\n",
					basename(argv[0]), conf);
			exit(EX_USAGE);
		}
		else if (stat(conf, &buf) != 0 || !(buf.st_mode & S_IFREG))
		{
			fprintf(stderr, "%s: Illegal config file: %s\n",
					basename(argv[0]), conf);
			exit(EX_USAGE);
		}
	}

	/* read configuration */
	if (read_config(conf) == MI_FAILURE)
	{
		fprintf(stderr, "%s: Error parsing config file: %s\n",
				basename(argv[0]), conf);
		exit(EX_DATAERR);
	}

	/* register callbacks */
	if (smfi_register(smfilter) == MI_FAILURE)
	{
		fprintf(stderr, "smfi_register failed\n");
		exit(EX_UNAVAILABLE);
	}

	/* start */
	return smfi_main();
}

/* eof */

