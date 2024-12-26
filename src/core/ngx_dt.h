/*
 * Copyright (C) George V. Neville-Neil
 */


#ifndef _NGX_DT_H_INCLUDED_
#define _NGX_DT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include "sqlite3.h"


void ngx_dt_connection(ngx_connection_t *conn, ngx_event_t *ev);

#endif /* _NGX_DT_H_INCLUDED_ */
