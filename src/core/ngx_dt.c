
/*
 * Copyright (C) George V. Neville-Neil
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include <ngx_dt.h>

#include <syslog.h> /* XXX - gnn debugging */
#include <sys/md5.h>

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


/* PUT THIS IN A LIBRARY FFS */

/* from osdb.h */

SLIST_HEAD(osdb_row_head, osdb_row);

typedef struct osdb_table {
	int num_columns;
	struct osdb_row_head *head;
} osdb_table;

typedef struct osdb_snap {
	STAILQ_ENTRY(osdb_snap) entries;
	int refcnt;
	struct timespec when; /* Timing for snapshots.*/
	MD5_CTX context;
	unsigned char digest[16];
	osdb_table *snap_table;
} osdb_snap;

STAILQ_HEAD(osdb_snap_head, osdb_snap);

typedef enum vtable_type {
	VTAB_PROCS,
	VTAB_THREADS,
	VTAB_TCPS,
	VTAB_UDPS,
	VTAB_FILES,
#ifndef WITHOUT_VNODE_TABLE
	VTAB_VNODES,
#endif // WITHOUT_VNODE_TABLE
#ifndef WITHOUT_INODE_TABLE
	VTAB_INODES,
#endif // WITHOUT_INODE_TABLE
#ifndef WITHOUT_DIRENT_TABLE
	VTAB_DIRENTS,
#endif // WITHOUT_DIRENT_TABLE
	VTAB_NFSCLIENT,
#ifndef WITHOUT_SUPERBLOCK_TABLE
	VTAB_SUPERBLOCKS,
#endif // WITHOUT_SUPERBLOCK_TABLE
} vtable_type;

typedef struct osdb_vtab {
	sqlite3_vtab base; /* Base class - must be first */
	const vtable_type type;
	const char *table_create;
	const char *name;
	struct osdb_snap_head snap;
	int snap_count;
	void (*lock)(void);
	void (*unlock)(void);
	void (*snapshot)(sqlite3_vtab *, struct timespec);
	int (*moduleinit)(sqlite3 *, char **, const sqlite3_api_routines *,
	    void *);
} osdb_vtab;

/* from osdb_value.h */

#define osdb_malloc(arg) malloc((arg))
#define osdb_free(arg) free((arg))

enum type_t { BLOB, DOUBLE, INT32, INT64, TEXT, TEXT16 };

typedef struct osdb_value {
	union {
		unsigned char *blob_value;
		double double_value;
		int32_t int32_value;
		int64_t int64_value;
		char *text_value;
		char *text16_value;
	};
	int size;
	enum type_t type;
} osdb_value;

typedef struct osdb_row {
	osdb_value **columns;
	SLIST_ENTRY(osdb_row) entry;
} osdb_row;


typedef struct osdb_table_iterator {
	osdb_row *cur;
} osdb_table_iterator;

/* from vtab_common.h */

typedef struct common_cursor common_cursor;
struct common_cursor {
	sqlite3_vtab_cursor base; /* Base class - must be first */
	sqlite3_vtab *vtab;	  /* Back pointer to the vtab */
	osdb_snap *cur_snap;
	osdb_table_iterator *it;
	osdb_row *row;
	osdb_table *table;
	sqlite_int64 iRowid;
};

void print_osdb_value(osdb_value *value);
void print_osdb_row(osdb_row *row, int num_columns);
void print_osdb_table(osdb_table *table);


osdb_value *
new_osdb_blob(unsigned char *x, int size, MD5_CTX *context)
{

	osdb_value *value = (osdb_value *)osdb_malloc(sizeof(osdb_value));
	if (!value) {
		return NULL;
	}
	value->blob_value = osdb_malloc(size * sizeof(unsigned char));
	if (!value->blob_value) {
		osdb_free(value);
		return NULL;
	}
	memcpy(value->blob_value, x, size);
	value->type = BLOB;
	value->size = size;
	return value;
}

osdb_value *
new_osdb_double(double x, MD5_CTX *context)
{

	osdb_value *value = (osdb_value *)osdb_malloc(sizeof(osdb_value));
	if (!value) {
		return NULL;
	}
	value->double_value = x;
	value->type = DOUBLE;
	return value;
}

osdb_value *
new_osdb_int32(int32_t x, MD5_CTX *context)
{
	osdb_value *value = (osdb_value *)osdb_malloc(sizeof(osdb_value));
	if (!value) {
		return NULL;
	}
	value->int32_value = x;
	value->type = INT32;
	return value;
}

osdb_value *
new_osdb_int64(int64_t x, MD5_CTX *context)
{
	osdb_value *value = (osdb_value *)osdb_malloc(sizeof(osdb_value));
	if (!value) {
		return NULL;
	}
	value->int64_value = x;
	value->type = INT64;
	if (context != NULL)
		MD5Update(context, (void *)&x, sizeof(x));
	return value;
}

osdb_value *
new_osdb_text(char *x, int size, MD5_CTX *context)
{

	osdb_value *value = (osdb_value *)osdb_malloc(sizeof(osdb_value));
	if (!value) {
		return NULL;
	}
	value->text_value = osdb_malloc(size * sizeof(char));
	if (!value->text_value) {
		osdb_free(value);
		return NULL;
	}
	memcpy(value->text_value, x, size);
	if (context != NULL)
		MD5Update(context, x, size);
	value->type = TEXT;
	value->size = size;
	return value;
}

osdb_value *
new_osdb_text16(char *x, int size, MD5_CTX *context)
{
	osdb_value *value = (osdb_value *)osdb_malloc(sizeof(osdb_value));
	if (!value) {
		return NULL;
	}
	value->text16_value = osdb_malloc(size * sizeof(char));
	if (!value->text16_value) {
		osdb_free(value);
		return NULL;
	}
	memcpy(value->text16_value, x, size);
	value->type = TEXT16;
	value->size = size;
	return value;
}

osdb_table *
new_osdb_table(int column_width)
{
	osdb_table *table = (osdb_table *)osdb_malloc(sizeof(osdb_table));
	if (!table) {
		return NULL;
	}
	table->head = (struct osdb_row_head *)osdb_malloc(
	    sizeof(struct osdb_row_head));
	SLIST_INIT(table->head);
	table->num_columns = column_width;
	return table;
}

void
free_osdb_column(osdb_value *value)
{
	if (!value) {
		return;
	}

	switch (value->type) {
	case BLOB:
		osdb_free(value->blob_value);
		break;
	case DOUBLE:
	case INT32:
		break;
	case INT64:
		break;
	case TEXT:
		osdb_free(value->text_value);
		break;
	case TEXT16:
		osdb_free(value->text16_value);
		break;
	}
	osdb_free(value);
}

void
free_osdb_row(osdb_row *row, int num_columns)
{
	if (!row) {
		return;
	}
	for (int i = 0; i < num_columns; i++) {
		free_osdb_column(row->columns[i]);
	}
	osdb_free(row->columns);
	osdb_free(row);
}

void
free_osdb_table(osdb_table *table)
{
	if (!table) {
		return;
	}
	osdb_row *cur = SLIST_FIRST(table->head);
	while (cur != NULL) {
		SLIST_REMOVE_HEAD(table->head, entry);
		free_osdb_row(cur, table->num_columns);
		cur = SLIST_FIRST(table->head);
	}
	osdb_free(table->head);
	osdb_free(table);
}

osdb_value **
new_osdb_columns(int column_width)
{
	osdb_value **row = (osdb_value **)osdb_malloc(
	    column_width * sizeof(osdb_value *));
	return row;
}

int
osdb_table_push(osdb_table *table, osdb_value **new_columns)
{
	osdb_row *new_row = (osdb_row *)osdb_malloc(sizeof(osdb_row));
	if (!new_row) {
		return 1;
	}
	new_row->columns = new_columns;
	SLIST_INSERT_HEAD(table->head, new_row, entry);
	return 0;
}

osdb_table_iterator *
new_osdb_table_iterator(osdb_table *table)
{
	osdb_table_iterator *it = (osdb_table_iterator *)osdb_malloc(
	    sizeof(osdb_table_iterator));
	if (!it) {
		return NULL;
	}
	it->cur = SLIST_FIRST(table->head);
	return it;
}

int
osdb_table_iterator_init(osdb_table_iterator *it, osdb_table *table)
{
	it->cur = SLIST_FIRST(table->head);
	return 0;
}

osdb_row *
osdb_table_iterator_next(osdb_table_iterator *it)
{
	osdb_row *cur = it->cur;
	if (cur != NULL) {
		it->cur = SLIST_NEXT(it->cur, entry);
	}
	return cur;
}

void
print_osdb_table(osdb_table *table)
{

	osdb_table_iterator *it = new_osdb_table_iterator(table);
	osdb_row *row = osdb_table_iterator_next(it);
	while (row != NULL) {
		print_osdb_row(row, table->num_columns);
		printf("\n");
		row = osdb_table_iterator_next(it);
	}
	osdb_free(it);
}

void
print_osdb_row(osdb_row *row, int num_columns)
{
	for (int i = 0; i < num_columns; i++) {
		if (i) {
			printf(", ");
		}
		print_osdb_value(row->columns[i]);
	}
}

void
print_osdb_value(osdb_value *value)
{

	switch (value->type) {
	case BLOB:
		printf("%*s", value->size, value->blob_value);
		break;
	case DOUBLE:
		printf("%f", value->double_value);
		break;
	case INT32:
		printf("%d", value->int32_value);
		break;
	case INT64:
		printf("%ld", value->int64_value);
		break;
	case TEXT:
		printf("%*s", value->size, value->text_value);
		break;
	case TEXT16:
		printf("%*s", value->size, value->text16_value);
		break;
	default:
		printf("print_osdb_value error");
		break;
	}
}




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
	return (sqlite3_declare_vtab(db, "CREATE TABLE x(fd INTEGER, start_time INTEGER, timestamp INTEGER)"));
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
** This method is the destructor for templatevtab_vtab objects.
*/
int
commonDisconnect(sqlite3_vtab *pVtab)
{
	return SQLITE_OK;
}

/*
** Constructor for a new templatevtab_cursor object.
*/
int
commonOpen(sqlite3_vtab *pVtab, sqlite3_vtab_cursor **ppCursor)
{
	common_cursor *pCur = (common_cursor *)osdb_malloc(sizeof(*pCur));

	if (!pCur) {
		return SQLITE_NOMEM;
	}
	*ppCursor = &pCur->base;

	pCur->vtab = pVtab;

	pCur->cur_snap = STAILQ_FIRST(&((struct osdb_vtab *)pCur->vtab)->snap);
	pCur->cur_snap->refcnt++;

	pCur->table = pCur->cur_snap->snap_table;

	pCur->it = new_osdb_table_iterator(pCur->table);
	pCur->row = osdb_table_iterator_next(pCur->it);
	return SQLITE_OK;
}

int
commonColumn(sqlite3_vtab_cursor *cur, /* The cursor */
    sqlite3_context *ctx, /* First argument to sqlite3_result_...() */
    int i		  /* Which column to return */
)
{
	common_cursor *pCur = (common_cursor *)cur;
	osdb_value *value = pCur->row->columns[i];
	switch (value->type) {
	case BLOB:
		// sqlite3_result_blob(ctx, value->blob_value);
		break;
	case DOUBLE:
		sqlite3_result_double(ctx, value->double_value);
		break;
	case INT32:
		sqlite3_result_int(ctx, value->int32_value);
		return SQLITE_OK;
	case INT64:
		sqlite3_result_int64(ctx, value->int64_value);
		return SQLITE_OK;
	case TEXT:
		sqlite3_result_text(ctx, value->text_value, -1,
		    SQLITE_TRANSIENT);
		return SQLITE_OK;
	case TEXT16:
		// sqlite3_result_text16be(ctx, value->text_value);
		break;
	}

	return SQLITE_ERROR;
}

int
commonNext(sqlite3_vtab_cursor *cur)
{
	common_cursor *pCur = (common_cursor *)cur;
	pCur->row = osdb_table_iterator_next(pCur->it);
	if (pCur->row == NULL) {
		pCur->cur_snap = STAILQ_NEXT(pCur->cur_snap, entries);
		if (pCur->cur_snap == NULL)
			goto out;
		pCur->cur_snap->refcnt++;

		pCur->table = pCur->cur_snap->snap_table;

		if (pCur->it != NULL) {
			osdb_free(pCur->it);
		}
		pCur->it = new_osdb_table_iterator(pCur->table);
		pCur->row = osdb_table_iterator_next(pCur->it);
	}

out:
	pCur->iRowid++;
	return SQLITE_OK;
}

int
commonEof(sqlite3_vtab_cursor *cur)
{

	common_cursor *pCur = (common_cursor *)cur;
	return (pCur->row == NULL);
}

int
commonFilter(sqlite3_vtab_cursor *pVtabCursor, int idxNum, const char *idxStr,
    int argc, sqlite3_value **argv)
{
	common_cursor *pCur = (common_cursor *)pVtabCursor;

	pCur->cur_snap = STAILQ_FIRST(&((struct osdb_vtab *)pCur->vtab)->snap);
	pCur->table = pCur->cur_snap->snap_table;

	if (pCur->it != NULL) {
		osdb_free(pCur->it);
	}
	pCur->it = new_osdb_table_iterator(pCur->table);

	osdb_table_iterator_init(pCur->it, pCur->table);
	pCur->row = osdb_table_iterator_next(pCur->it);
	pCur->iRowid = 0;
	return SQLITE_OK;
}

int
commonClose(sqlite3_vtab_cursor *cur)
{
	common_cursor *pCur = (common_cursor *)cur;
	osdb_free(pCur->it);
	osdb_free(pCur);
	return SQLITE_OK;
}

int
commonRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
	common_cursor *pCur = (common_cursor *)cur;
	*pRowid = pCur->iRowid;
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
	/* xDisconnect */ commonDisconnect,
	/* xDestroy    */ commonDebugDestroy,
	/* xOpen       */ commonOpen,
	/* xClose      */ commonClose,
	/* xFilter     */ commonFilter,
	/* xNext       */ commonNext,
	/* xEof        */ commonEof,
	/* xColumn     */ commonColumn,
	/* xRowid      */ commonRowid,
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
	sqlite3_open_v2(":memory:", &db,
	    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |SQLITE_OPEN_FULLMUTEX, NULL)) {
	    return NULL;
    }

    SQLITE_EXTENSION_INIT2(NULL);
    if (&ngx_dt_null_module == &ngx_dt_null_module+1)
	    exit(1);
    
    if (SQLITE_OK != sqlite3_create_module(db,
	    "ngx", &ngx_dt_null_module, fcf)) {
	    return NULL;
    }
    
    /* if (SQLITE_OK != sqlite3_exec(fcf->db, "CREATE TABLE foo (fd INTEGER, start_time INTEGER, timestamp INTEGER);", */
    /* 	    0, 0, &zErrMsg)) { */
    /* 	    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, zErrMsg); */
    /* 	    return NULL; */
    /* } */

    /* if (SQLITE_OK != sqlite3_exec(fcf->db, "INSERT INTO foo VALUES (7, 13909062, 1736322307);", */
    /* 	    0, 0, &zErrMsg)) { */
    /* 	    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, zErrMsg); */
    /* 	    return NULL; */
    /* } */

	
    if (SQLITE_OK != sqlite3_exec(db, "CREATE VIRTUAL TABLE ngx USING ngx()",
	    0, 0, &zErrMsg)) {
	    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, zErrMsg);
	    return NULL;
    }

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Data Tracing Module is enabled");

    return NGX_CONF_OK;
}

static int
ngx_dt_cb(void *ctx, int columns, char **data, char **col_names)
{
	ngx_log_t *log = (ngx_log_t *)ctx;

	for (int i = 0; i < columns; i++)
		ngx_log_error(NGX_LOG_NOTICE, log, 0, "%s", data[0][i]);

	return 1;
}

void
ngx_dt_connection(ngx_connection_t *conn, ngx_event_t *ev)
{
	
	int retval = SQLITE_OK;
	struct timespec tp;
	char *zErrMsg = 0;
	char *cmd = malloc(2048);
	
	ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "Tracing connection %d msec %d", conn->number, conn->start_time);

	clock_gettime(CLOCK_REALTIME_PRECISE, &tp);

	sprintf(cmd, "INSERT INTO ngx VALUES (%d, %d, %ld);",
	    conn->fd, (int)conn->start_time, tp.tv_sec);

	retval = sqlite3_exec(db, cmd, ngx_dt_cb, ev->log, &zErrMsg);
	if (retval != SQLITE_OK) {
		if (zErrMsg != NULL) {
			ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, zErrMsg);
		} else {
			ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "SQLITE ERROR: retval %d", retval);
		}
		return;
	}
	retval = sqlite3_exec(db, "select * from ngx;", ngx_dt_cb, ev->log, &zErrMsg);
	if (retval != SQLITE_OK) {
		if (zErrMsg != NULL) {
			ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, zErrMsg);
		} else {
			ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "SQLITE ERROR: retval %d", retval);
		}
		return;
	}

}
