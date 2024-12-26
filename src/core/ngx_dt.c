
/*
 * Copyright (C) George V. Neville-Neil
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include <ngx_dt.h>

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
    
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Data Tracing Module is enabled");


    return NGX_CONF_OK;
}

void
ngx_dt_connection(ngx_connection_t *conn, ngx_event_t *ev)
{
	
	ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "Tracing connection %d msec %d", conn->number, conn->start_time);

}
