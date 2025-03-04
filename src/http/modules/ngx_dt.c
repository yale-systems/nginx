
/*
 * Copyright (C) George V. Neville-Neil
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_connection.h>
#include <ngx_http.h>

#include <ngx_dt.h>

#include <syslog.h> /* XXX - gnn debugging */

#include "dbsc/dbsc.h"
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

enum col {DT_CONN_TYPE, DT_CONN_BUFFERED, DT_CONN_LOG_ERROR,
	DT_CONN_TIMEDOUT, DT_CONN_ERROR, DT_CONN_DESTROYED,
	DT_CONN_PIPELINE, DT_CONN_IDLE, DT_CONN_REUSABLE, DT_CONN_CLOSE,
	DT_CONN_SHARED, DT_CONN_SENDFILE, DT_CONN_SNDLOWAT,
	DT_CONN_TCP_NODELAY, DT_CONN_TCP_NOPUSH, DT_CONN_NEED_LAST_BUF,
	DT_CONN_NEED_FLUSH_BUF, DT_CONN_TIMESTAMP, DT_CONN_MAX};

static int
ngx_dt_conn_columns(dbsc_value **columns, ngx_connection_t *conn,
    struct timespec *when, DBSC_DIGEST_CTX *ctx)
{

	columns[DT_CONN_TYPE] = new_dbsc_int64(conn->type, ctx);
	columns[DT_CONN_BUFFERED] = new_dbsc_int64(conn->buffered, ctx);
	columns[DT_CONN_LOG_ERROR] = new_dbsc_int64(conn->log_error, ctx);
	columns[DT_CONN_TIMEDOUT] = new_dbsc_int64(conn->timedout, ctx);
	columns[DT_CONN_ERROR] = new_dbsc_int64(conn->error, ctx);
	columns[DT_CONN_DESTROYED] = new_dbsc_int64(conn->destroyed, ctx);
	columns[DT_CONN_PIPELINE] = new_dbsc_int64(conn->pipeline, ctx);
	columns[DT_CONN_IDLE] = new_dbsc_int64(conn->idle, ctx);
	columns[DT_CONN_REUSABLE] = new_dbsc_int64(conn->reusable, ctx);
	columns[DT_CONN_CLOSE] = new_dbsc_int64(conn->close, ctx);
	columns[DT_CONN_SHARED] = new_dbsc_int64(conn->shared, ctx);
	columns[DT_CONN_SENDFILE] = new_dbsc_int64(conn->sendfile, ctx);
	columns[DT_CONN_SNDLOWAT] = new_dbsc_int64(conn->sndlowat, ctx);
	columns[DT_CONN_TCP_NODELAY] = new_dbsc_int64(conn->tcp_nodelay, ctx);
	columns[DT_CONN_TCP_NOPUSH] = new_dbsc_int64(conn->tcp_nopush, ctx);
	columns[DT_CONN_NEED_LAST_BUF] = new_dbsc_int64(conn->need_last_buf, ctx);
	columns[DT_CONN_NEED_FLUSH_BUF] = new_dbsc_int64(conn->need_flush_buf, ctx);

	columns[DT_CONN_TIMESTAMP] = new_dbsc_int64(when->tv_sec, NULL);

	return SQLITE_OK;
}

/*
 * This MUST be called while locks, above, are held.
 */

struct snapshot_args {
	dbsc_tab *tab;
};

void
ngx_dt_conn_snapshot(void *arg, struct timespec *when)
{

	struct snapshot_args *args = (struct snapshot_args *)arg;
	dbsc_tab *pDtab = args->tab;
	dbsc_snap *snap = dbsc_malloc(sizeof(struct dbsc_snap));
	ngx_connection_t *conn;

	snap->snap_table = new_dbsc_table(DT_CONN_MAX);

	dbsc_digest_init(snap->context);

	conn = ngx_cycle->connections;

	for (ngx_uint_t i = 0; i < ngx_cycle->connection_n; i++) {
		dbsc_value **columns = new_dbsc_columns(DT_CONN_MAX);
		if (!columns) {
			return;
		}
		ngx_dt_conn_columns(columns, &conn[i], when,
		    snap->context);
		dbsc_table_push(snap->snap_table, columns);
        }

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
    char *create = "CREATE VIRTUAL TABLE conn USING conn()";

    lib = dbsc_init(1);

    if (lib == NULL) {
	    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Could not initialize DBSC.\n");
	    exit(1);
    }
    
    snap_args = dbsc_malloc(sizeof(struct snapshot_args));

    tab = dbsc_alloc(lib, "conn",
	"CREATE TABLE x(DT_CONN_TYPE INTEGER, DT_CONN_BUFFERED INTEGER, DT_CONN_LOG_ERROR INTEGER, DT_CONN_TIMEDOUT INTEGER, DT_CONN_ERROR INTEGER, DT_CONN_DESTROYED INTEGER, DT_CONN_PIPELINE INTEGER, DT_CONN_IDLE INTEGER, DT_CONN_REUSABLE INTEGER, DT_CONN_CLOSE INTEGER, DT_CONN_SHARED INTEGER, DT_CONN_SENDFILE INTEGER, DT_CONN_SNDLOWAT INTEGER, DT_CONN_TCP_NODELAY INTEGER, DT_CONN_TCP_NOPUSH INTEGER, DT_CONN_NEED_LAST_BUF INTEGER, DT_CONN_NEED_FLUSH_BUF INTEGER, timestamp INTEGER)",
	NULL, NULL, ngx_dt_conn_snapshot, snap_args, row_best_index);

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

