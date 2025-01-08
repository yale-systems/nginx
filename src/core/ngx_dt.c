
/*
 * Copyright (C) George V. Neville-Neil
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include <ngx_dt.h>

#include <syslog.h> /* XXX - gnn debugging */

#include "sqlite3ext.h"
SQLITE_EXTENSION_INIT1

typedef struct {
	ngx_flag_t  enable;
	sqlite3 *db;
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


/*
** The templatevtabConnect() method is invoked to create a new
** template virtual table.
**
** Think of this routine as the constructor for templatevtab_vtab objects.
**
** All this routine needs to do is:
**
**    (1) Allocate the templatevtab_vtab object and initialize all fields.
**
**    (2) Tell SQLite (via the sqlite3_declare_vtab() interface) what the
**        result set of queries against the virtual table will look like.
*/
static int
commonConnect(sqlite3 *db, void *pAux, int argc, const char *const *argv,
    sqlite3_vtab **ppVtab, char **pzErr)
{
	*ppVtab = (sqlite3_vtab *)pAux;

	if (pAux == NULL) {
		return (SQLITE_ERROR);
	}
	return (sqlite3_declare_vtab(db, "CREATE TABLE x(pid INTEGER, uid INTEGER, name VARCHAR(99), group_id INTEGER, tty VARCHAR(99), state VARCHAR(99), parent_pid INTEGER, timestamp INTEGER)"));
}


static int
commonCreate(sqlite3 *db, void *pAux, int argc, const char *const *argv,
    sqlite3_vtab **ppVtab, char **pzErr)
{
	return commonConnect(db, pAux, argc, argv, ppVtab, pzErr);
}

static int
commonDebugBestIndex(sqlite3_vtab *pVTab, sqlite3_index_info* foo)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}

static  int
commonDebugDisconnect(sqlite3_vtab *pVTab)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
	
static int
commonDebugDestroy(sqlite3_vtab *pVTab)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}

static int
commonDebugOpen(sqlite3_vtab *pVTab, sqlite3_vtab_cursor **ppCursor)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}

static int
commonDebugClose(sqlite3_vtab_cursor *nil)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
static int
commonDebugFilter(sqlite3_vtab_cursor *nil, int idxNum, const char *idxStr,
                int argc, sqlite3_value **argv)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
static int
commonDebugNext(sqlite3_vtab_cursor *nil)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
static int
commonDebugEof(sqlite3_vtab_cursor *nil)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
static int
commonDebugColumn(sqlite3_vtab_cursor *nil, sqlite3_context *ctx, int zero)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
static int
commonDebugRowid(sqlite3_vtab_cursor *nil, sqlite3_int64 *pRowid)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
static int
commonDebugUpdate(sqlite3_vtab *nil, int zero, sqlite3_value **val,
    sqlite3_int64 *ival)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
static int
commonDebugBegin(sqlite3_vtab *pVTab)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
static int
commonDebugSync(sqlite3_vtab *pVTab)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
static int
commonDebugCommit(sqlite3_vtab *pVTab)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
static int
commonDebugRollback(sqlite3_vtab *pVTab)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
static int
commonDebugFindFunction(sqlite3_vtab *pVtab, int nArg, const char *zName,
                       void (**pxFunc)(sqlite3_context*,int,sqlite3_value**),
                       void **ppArg)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
static int
commonDebugRename(sqlite3_vtab *pVtab, const char *zNew)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
  /* The methods above are in version 1 of the sqlite_module object. Those
  ** below are for version 2 and greater. */
static int
commonDebugSavepoint(sqlite3_vtab *pVTab, int zero)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
static int
commonDebugRelease(sqlite3_vtab *pVTab, int zero)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
static int
commonDebugRollbackTo(sqlite3_vtab *pVTab, int zero)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
  /* The methods above are in versions 1 and 2 of the sqlite_module object.
  ** Those below are for version 3 and greater. */
static int
commonDebugShadowName(const char *nil)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}
  /* The methods above are in versions 1 through 3 of the sqlite_module object.
  ** Those below are for version 4 and greater. */
static int
commonDebugIntegrity(sqlite3_vtab *pVTab, const char *zSchema,
                    const char *zTabName, int mFlags, char **pzErr)
{
	syslog(LOG_EMERG, "%s called!", __func__);
	return SQLITE_OK;
}

/*
** This following structure defines all the methods for the
** virtual table.
*/
static sqlite3_module ngx_dt_null_module = {
	/* iVersion    */ 42,
	/* xCreate     */ commonCreate,
	/* xConnect    */ commonConnect,
	/* xBestIndex  */ commonDebugBestIndex,
	/* xDisconnect */ commonDebugDisconnect,
	/* xDestroy    */ commonDebugDestroy,
	/* xOpen       */ commonDebugOpen,
	/* xClose      */ commonDebugClose,
	/* xFilter     */ commonDebugFilter,
	/* xNext       */ commonDebugNext,
	/* xEof        */ commonDebugEof,
	/* xColumn     */ commonDebugColumn,
	/* xRowid      */ commonDebugRowid,
	/* xUpdate     */ commonDebugUpdate,
	/* xBegin      */ commonDebugBegin,
	/* xSync       */ commonDebugSync,
	/* xCommit     */ commonDebugCommit,
	/* xRollback   */ commonDebugRollback,
	/* xFindMethod */ commonDebugFindFunction,
	/* xRename     */ commonDebugRename,
	/* xSavepoint  */ commonDebugSavepoint,
	/* xRelease    */ commonDebugRelease,
	/* xRollbackTo */ commonDebugRollbackTo,
	/* xShadowName */ commonDebugShadowName,
	/* xIntegrity  */ commonDebugIntegrity
};

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


static char *
ngx_dt_enable(ngx_conf_t *cf, void *post, void *data)
{
    ngx_dt_conf_t  *fcf = data;
    char *zErrMsg = 0;
    int retval;

    if (fcf->enable == 0) {
        return NGX_CONF_OK;
    }
    retval = sqlite3_initialize();
    if (SQLITE_OK != retval) {
	    return NULL;
    }
    
    if (SQLITE_OK !=
	sqlite3_open_v2(":memory:", &fcf->db,
	    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
	    return NULL;
    }

    SQLITE_EXTENSION_INIT2(NULL);
    if (SQLITE_OK != sqlite3_create_module(fcf->db,
	    "ngx", &ngx_dt_null_module, fcf)) {
	    return NULL;
    }
    
    if (SQLITE_OK != sqlite3_exec(fcf->db, "CREATE VIRTUAL TABLE ngx USING ngx()",
	    0, 0, &zErrMsg)) {
	    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, zErrMsg);
	    return NULL;
    }
    
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Data Tracing Module is enabled");

    return NGX_CONF_OK;
}

void
ngx_dt_connection(ngx_connection_t *conn, ngx_event_t *ev)
{
	
	ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "Tracing connection %d msec %d", conn->number, conn->start_time);

}
