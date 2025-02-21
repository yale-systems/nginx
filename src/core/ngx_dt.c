
/*
 * Copyright (C) George V. Neville-Neil
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include <ngx_dt.h>

#include <syslog.h> /* XXX - gnn debugging */

#include "../../../dbsc-gnn-lib/src/dbsidecar/include/dbsc/dbsc.h"
#include "sqlite3ext.h"
SQLITE_EXTENSION_INIT1

sqlite3 *db;

typedef struct {
	ngx_flag_t  enable;
} ngx_dt_conf_t;


static void *ngx_dt_create_conf(ngx_cycle_t *cycle);
static char *ngx_dt_init_conf(ngx_cycle_t *cycle, void *conf);

static char *ngx_dt_enable(ngx_conf_t *cf, void *post, void *data);
static ngx_conf_post_t  ngx_dt_enable_post = { ngx_dt_enable };


static ngx_command_t  ngx_dt_commands[] = {

    { ngx_string("dt_enabled"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_dt_conf_t, enable),
      &ngx_dt_enable_post },

      ngx_null_command
};


static ngx_core_module_t  ngx_dt_module_ctx = {
    ngx_string("dt"),
    ngx_dt_create_conf,
    ngx_dt_init_conf
};


ngx_module_t  ngx_dt_module = {
    NGX_MODULE_V1,
    &ngx_dt_module_ctx,                   /* module context */
    ngx_dt_commands,                      /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


#if 0 /* XXX - gnn */

enum col { VT_NGX_FD, VT_NGX_START_TIME, VT_NGX_TIMESTAMP };

static int
ngx_dt_copy_columns(struct proc *curProc, dbsc_value **columns, struct timespec *when,
    DBSC_DIGEST_CTX *context)
{

	columns[VT_NGX_FD] = new_dbsc_int64(curProc->p_pid, context);
	columns[VT_NGX_START_TIME] = new_dbsc_int64(curProc->p_ucred->cr_uid,
	    context);
	columns[VT_NGX_TIMESTAMP] = new_dbsc_int64(when->tv_sec, NULL);
	return SQLITE_OK;
}

/*
 * This MUST be called while locks, above, are held.
 */

void
ngx_dt_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{

	dbsc_snap *snap = dbsc_malloc(sizeof(struct dbsc_snap));

	snap->when = when;

	snap->snap_table = new_dbsc_table(VT_PROC_NUM_COLUMNS);

	MD5Init(&snap->context);

	while (prc) {
		dbsc_value **columns = new_dbsc_columns(VT_PROC_NUM_COLUMNS);
		if (!columns) {
			return;
		}
		copy_columns(prc, columns, &snap->when, &snap->context);
		dbsc_table_push(snap->snap_table, columns);

		prc = LIST_NEXT(prc, p_list);
	}

	MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
	printf("proc digest: ");
	for (size_t i = 0; i < 16; i++) {
		printf("%02hhx", snap->digest[i]);
	}
	printf("\n");
#endif
	dbsc_snapshot_rotate((struct dbsc_tab *)pVtab, snap);
}
#endif

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


static void *
ngx_dt_create_conf(ngx_cycle_t *cycle)
{
    ngx_dt_conf_t  *fcf;

    fcf = ngx_pcalloc(cycle->pool, sizeof(ngx_dt_conf_t));
    if (fcf == NULL) {
        return NULL;
    }

    fcf->enable = NGX_CONF_UNSET;

    return fcf;
}


static char *
ngx_dt_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_dt_conf_t *fcf = conf;

    ngx_conf_init_value(fcf->enable, 0);

    return NGX_CONF_OK;
}


static dbsc *lib;

static char *
ngx_dt_enable(ngx_conf_t *cf, void *post, void *data)
{
    ngx_dt_conf_t  *fcf = data;

    dbsc_tab *tab;
    char *create = "CREATE VIRTUAL TABLE ngx USING ngx()";
/*
    char *zErrMsg = 0;
    int retval;
*/
    if (fcf->enable == 0) {
        return NGX_CONF_OK;
    }

    lib = dbsc_init();

    if (lib == NULL) {
	    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Could not initialize DBSC.\n");
	    exit(1);
    }
    
    tab = dbsc_alloc(lib, "test",
	"CREATE TABLE x(FD INTEGER PRIMARY KEY NOT NULL,  INTEGER START, INTEGER TIMESTAMP)",
	NULL, NULL, row_best_index);

    if (tab == NULL) {
	    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Could not create table.\n");
	    exit(1);
    }


    lib->exec(lib, create, strlen(create), NULL, 0);
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Data Tracing Module is enabled");


    return NGX_CONF_OK;
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

void
ngx_dt_connection(ngx_connection_t *conn, ngx_event_t *ev)
{
	
	int retval = SQLITE_OK;
	struct timespec tp;
	char *select = "select * from ngx;";
	char *zErrMsg = 0;
	char *cmd = malloc(2048);
	
	ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "Tracing connection %d msec %d", conn->number, conn->start_time);

	clock_gettime(CLOCK_REALTIME, &tp);

	sprintf(cmd, "INSERT INTO ngx VALUES (%d, %d, %ld);",
	    conn->fd, (int)conn->start_time, tp.tv_sec);

	retval = lib->exec(lib, cmd, strlen(cmd), NULL, 0);
	if (retval != SQLITE_OK) {
		if (zErrMsg != NULL) {
			ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, zErrMsg);
		} else {
			ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "SQLITE ERROR: retval %d", retval);
		}
		return;
	}
	retval = lib->exec(lib, select, strlen(select), NULL, 0);
	if (retval != SQLITE_OK) {
		if (zErrMsg != NULL) {
			ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, zErrMsg);
		} else {
			ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "SQLITE ERROR: retval %d", retval);
		}
		return;
	}

}
