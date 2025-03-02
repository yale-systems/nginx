
/*
 * Copyright (C) George V. Neville-Neil
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_dt.h>

#include <syslog.h> /* XXX - gnn debugging */

#include "../../../../osdb/src/dbsidecar/include/dbsc/dbsc.h"
#include "sqlite3ext.h"

static char *ngx_dt_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *data);

static ngx_command_t  ngx_dt_commands[] = {

    { ngx_string("data_tracing"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_dt_enable,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_dt_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_dt_module = {
    NGX_MODULE_V1,
    &ngx_http_dt_module_ctx,                   /* module context */
    ngx_dt_commands,                      /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static dbsc *lib;

enum col { NGX_MODULES_N, NGX_MODULES_USED, NGX_TIMESTAMP };
#define NUM_COLUMNS 3

static int
ngx_dt_copy_columns(dbsc_value **columns, struct timespec *when,
    DBSC_DIGEST_CTX *context)
{

	columns[NGX_MODULES_N] = new_dbsc_int64(ngx_cycle->modules_n, context);
	columns[NGX_MODULES_USED] = new_dbsc_int64(ngx_cycle->modules_used,
	    context);
	columns[NGX_TIMESTAMP] = new_dbsc_int64(when->tv_sec, NULL);
	return SQLITE_OK;
}

/*
 * This MUST be called while locks, above, are held.
 */

struct snapshot_args {
	dbsc_tab *tab;
};

void
ngx_dt_snapshot(void *arg, struct timespec *when)
{

	struct snapshot_args *args = (struct snapshot_args *)arg;
	dbsc_tab *pDtab = args->tab;
	dbsc_snap *snap = dbsc_malloc(sizeof(struct dbsc_snap));

	snap->snap_table = new_dbsc_table(NUM_COLUMNS);

	dbsc_digest_init(&snap->context);

	dbsc_value **columns = new_dbsc_columns(NUM_COLUMNS);
	if (!columns) {
		return;
	}
	ngx_dt_copy_columns(columns, when, &snap->context);
	dbsc_table_push(snap->snap_table, columns);
	
#ifdef DEBUG
	printf("proc digest: ");
	for (size_t i = 0; i < 16; i++) {
		printf("%02hhx", snap->digest[i]);
	}
	printf("\n");
#endif
	dbsc_snapshot_rotate((struct dbsc_tab *)pDtab, snap);
}


/*
** SQLite will invoke this method one or more times while planning a query
** that uses the virtual table.  This routine needs to create
** a query plan for each invocation and compute an estimated cost for that
** plan.
*/
int
row_best_index(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
	pIdxInfo->estimatedCost = (double)10;
	pIdxInfo->estimatedRows = 10;
	return SQLITE_OK;
}


#if 0 /* XXX- gnn */
static int
ngx_dt_cb(void *ctx, int columns, char **data, char **col_names)
{
	ngx_log_t *log = (ngx_log_t *)ctx;

	for (int i = 0; i < columns; i++)
		ngx_log_error(NGX_LOG_NOTICE, log, 0, "%s", data[0][i]);

	return 1;
}
#endif

ngx_int_t
ngx_dt_handler(ngx_http_request_t *request)
{
	
	ngx_connection_t *conn = request->connection;

	int retval = SQLITE_OK;
	struct timespec tp;
	char *select = "select * from ngx;";
	char *zErrMsg = 0;
	char *cmd = malloc(2048);
	
	abort();

	ngx_log_error(NGX_LOG_NOTICE, conn->log, 0,
	    "Tracing connection %d msec %d", conn->number, conn->start_time);

	clock_gettime(CLOCK_REALTIME, &tp);

	sprintf(cmd, "INSERT INTO ngx VALUES (%d, %d, %ld);",
	    conn->fd, (int)conn->start_time, tp.tv_sec);

	retval = lib->exec(lib, cmd, strlen(cmd), NULL, 0);
	if (retval != SQLITE_OK) {
		if (zErrMsg != NULL) {
			ngx_log_error(NGX_LOG_NOTICE, conn->log, 0, zErrMsg);
		} else {
			ngx_log_error(NGX_LOG_NOTICE, conn->log, 0, "SQLITE ERROR: retval %d", retval);
		}
		return NGX_ERROR;
	}
	retval = lib->exec(lib, select, strlen(select), NULL, 0);
	if (retval != SQLITE_OK) {
		if (zErrMsg != NULL) {
			ngx_log_error(NGX_LOG_NOTICE, conn->log, 0, zErrMsg);
		} else {
			ngx_log_error(NGX_LOG_NOTICE, conn->log, 0, "SQLITE ERROR: retval %d", retval);
		}
		return NGX_ERROR;
	}

	return NGX_OK;
}

static char *
ngx_dt_enable(ngx_conf_t *cf, ngx_command_t *cmf, void *conf)
{
#if 0
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
#endif
    dbsc_tab *tab;
    struct snapshot_args *snap_args = dbsc_malloc(sizeof(struct snapshot_args));
    char *create = "CREATE VIRTUAL TABLE ngx USING ngx()";

/*
    char *zErrMsg = 0;
    int retval;

    if (cf->enable == 0) {
        return NGX_CONF_OK;
    }
*/
    lib = dbsc_init(1);

    if (lib == NULL) {
	    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Could not initialize DBSC.\n");
	    exit(1);
    }
    
    snap_args = dbsc_malloc(sizeof(struct snapshot_args));

    tab = dbsc_alloc(lib, "ngx",
	"CREATE TABLE x(IVAL INTEGER PRIMARY KEY NOT NULL, USED INTEGER, TIMESTAMP INTEGER)",
	NULL, NULL, ngx_dt_snapshot, snap_args, row_best_index);

    if (tab == NULL) {
	    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Could not create table.\n");
	    exit(1);
    }

    /*
     * NB: This is annouyingly complex.  The args require the
     * allocated tab so we'll have to assign that inside the
     * allocator.  Surely there is a better way.
     */
    
    snap_args->tab = tab;

    lib->exec(lib, create, strlen(create), NULL, 0);

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Data Tracing Module is enabled");

#if 0

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NULL;
    }

    *h = ngx_dt_handler;
#endif
    return NGX_CONF_OK;
}

