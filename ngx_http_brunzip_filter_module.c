/*
 * Copyright (C) X4B
 * Copyright (C) Mathew Heard
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <brotli/decode.h>
#include <brotli/encode.h>

typedef struct {
    ngx_flag_t           enable;
    ngx_bufs_t           bufs;
} ngx_http_brunzip_conf_t;

typedef enum {
	FLUSH_NO_FLUSH = 0,
	FLUSH_FLUSH = 1,
	FLUSH_PROCESS = 2,
	FLUSH_FINISH = 3
} BrotliFlushStates;

typedef struct {
    ngx_chain_t         *in;
    ngx_chain_t         *free;
    ngx_chain_t         *busy;
    ngx_chain_t         *out;
    ngx_chain_t        **last_out;

    ngx_buf_t           *in_buf;
    ngx_buf_t           *out_buf;
    ngx_int_t            bufs;

    BrotliDecoderState   *bro;
	
    uint8_t             *input;
    uint8_t             *output;
    uint8_t             *next_in;
    uint8_t             *next_out;
    size_t               available_in;
    size_t               available_out;
	size_t               total_out;
	
    unsigned             started:1;
    BrotliFlushStates    flush:2;
    unsigned             redo:1;
    unsigned             done:1;
    unsigned             nomem:1;

    ngx_http_request_t  *request;
} ngx_http_brunzip_ctx_t;


static ngx_int_t ngx_http_brunzip_filter_inflate_start(ngx_http_request_t *r,
    ngx_http_brunzip_ctx_t *ctx);
static ngx_int_t ngx_http_brunzip_filter_add_data(ngx_http_request_t *r,
    ngx_http_brunzip_ctx_t *ctx);
static ngx_int_t ngx_http_brunzip_filter_get_buf(ngx_http_request_t *r,
    ngx_http_brunzip_ctx_t *ctx);
static ngx_int_t ngx_http_brunzip_filter_inflate(ngx_http_request_t *r,
    ngx_http_brunzip_ctx_t *ctx);
static ngx_int_t ngx_http_brunzip_filter_inflate_end(ngx_http_request_t *r,
    ngx_http_brunzip_ctx_t *ctx);

static void *ngx_http_brunzip_filter_alloc(void *opaque, u_int items,
    u_int size);
static void ngx_http_brunzip_filter_free(void *opaque, void *address);

static ngx_int_t ngx_http_brunzip_filter_init(ngx_conf_t *cf);
static void *ngx_http_brunzip_create_conf(ngx_conf_t *cf);
static char *ngx_http_brunzip_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_command_t  ngx_http_brunzip_filter_commands[] = {

    { ngx_string("brunzip"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brunzip_conf_t, enable),
      NULL },

    { ngx_string("brunzip_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brunzip_conf_t, bufs),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_brunzip_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_brunzip_filter_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_brunzip_create_conf,           /* create location configuration */
    ngx_http_brunzip_merge_conf             /* merge location configuration */
};


ngx_module_t  ngx_http_brunzip_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_brunzip_filter_module_ctx,    /* module context */
    ngx_http_brunzip_filter_commands,       /* module directives */
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


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_int_t
accept_br(ngx_table_elt_t *ae)
{
    size_t          len;
    unsigned char  *ptr;

    if (!ae) {
        return NGX_DECLINED;
    }

    if (ae->value.len < 2) {
        return NGX_DECLINED;
    }

    ptr = ae->value.data;
    len = ae->value.len;

    while (len >= 2) {

        len--;

        if (*ptr++ != 'b') {
            continue;
        }

        if (*ptr == 'r') {
            if (len == 1) {
                return NGX_OK;
            }

            if (*(ptr + 1) == ',' || *(ptr + 1) == ';' || *(ptr + 1) == ' ') {
                return NGX_OK;
            }
        }
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_brunzip_header_filter(ngx_http_request_t *r)
{
    ngx_http_brunzip_ctx_t   *ctx;
    ngx_http_brunzip_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brunzip_filter_module);

    /* TODO support multiple content-codings */
    /* TODO always brunzip - due to configuration or module request */
    /* TODO ignore content encoding? */

    if (!conf->enable
        || r->headers_out.content_encoding == NULL
        || accept_br(r->headers_out.content_encoding) == NGX_OK)
    {
        return ngx_http_next_header_filter(r);
    }

    //r->gzip_vary = 1;

	if (accept_br(r->headers_in.accept_encoding) != NGX_OK) {
		return ngx_http_next_header_filter(r);
	}

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_brunzip_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_brunzip_filter_module);

    ctx->request = r;

    r->filter_need_in_memory = 1;

    r->headers_out.content_encoding->hash = 0;
    r->headers_out.content_encoding = NULL;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_brunzip_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                     rc;
    ngx_uint_t              flush;
    ngx_chain_t            *cl;
    ngx_http_brunzip_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brunzip_filter_module);

    if (ctx == NULL || ctx->done) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http brunzip filter");

    if (!ctx->started) {
        if (ngx_http_brunzip_filter_inflate_start(r, ctx) != NGX_OK) {
            goto failed;
        }
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            goto failed;
        }
    }

    if (ctx->nomem) {

        /* flush busy buffers */

        if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
            goto failed;
        }

        cl = NULL;

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (ngx_buf_tag_t) &ngx_http_brunzip_filter_module);
        ctx->nomem = 0;
        flush = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            /* cycle while there is data to feed zlib and ... */

            rc = ngx_http_brunzip_filter_add_data(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }


            /* ... there are buffers to write zlib output */

            rc = ngx_http_brunzip_filter_get_buf(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_ERROR) {
                goto failed;
            }

            rc = ngx_http_brunzip_filter_inflate(r, ctx);

            if (rc == NGX_OK) {
                break;
            }

            if (rc == NGX_ERROR) {
                goto failed;
            }

            /* rc == NGX_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            return ctx->busy ? NGX_AGAIN : NGX_OK;
        }

        rc = ngx_http_next_body_filter(r, ctx->out);

        if (rc == NGX_ERROR) {
            goto failed;
        }

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (ngx_buf_tag_t) &ngx_http_brunzip_filter_module);
        ctx->last_out = &ctx->out;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "brunzip out: %p", ctx->out);

        ctx->nomem = 0;
        flush = 0;

        if (ctx->done) {
            return rc;
        }
    }

    /* unreachable */

failed:

    ctx->done = 1;

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_brunzip_filter_inflate_start(ngx_http_request_t *r,
    ngx_http_brunzip_ctx_t *ctx)
{
    int  rc;

    ctx->bro = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (ctx->bro == NULL) {
        return NGX_ERROR;
    }

    if (rc != BROTLI_TRUE) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "inflateInit2() failed: %d", rc);
        return NGX_ERROR;
    }

    ctx->started = 1;

    ctx->last_out = &ctx->out;

    return NGX_OK;
}


static ngx_int_t
ngx_http_brunzip_filter_add_data(ngx_http_request_t *r,
    ngx_http_brunzip_ctx_t *ctx)
{
    if (ctx->available_in || ctx->flush != FLUSH_PROCESS || ctx->redo) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "brunzip in: %p", ctx->in);

    if (ctx->in == NULL) {
        return NGX_DECLINED;
    }

    ctx->in_buf = ctx->in->buf;
    ctx->in = ctx->in->next;

    ctx->next_in = ctx->in_buf->pos;
    ctx->available_in = ctx->in_buf->last - ctx->in_buf->pos;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "brunzip in_buf:%p ni:%p ai:%ud",
                   ctx->in_buf,
                   ctx->next_in, ctx->available_in);

    if (ctx->in_buf->last_buf || ctx->in_buf->last_in_chain) {
        ctx->flush = FLUSH_FINISH;
    } else if (ctx->in_buf->flush) {
        ctx->flush = FLUSH_FLUSH;
    } else if (ctx->available_in == 0) {
        ctx->flush = FLUSH_NO_FLUSH;
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_brunzip_filter_get_buf(ngx_http_request_t *r,
    ngx_http_brunzip_ctx_t *ctx)
{
    ngx_http_brunzip_conf_t  *conf;

    if (ctx->available_out) {
        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brunzip_filter_module);

    if (ctx->free) {
        ctx->out_buf = ctx->free->buf;
        ctx->free = ctx->free->next;

        ctx->out_buf->flush = 0;

    } else if (ctx->bufs < conf->bufs.num) {

        ctx->out_buf = ngx_create_temp_buf(r->pool, conf->bufs.size);
        if (ctx->out_buf == NULL) {
            return NGX_ERROR;
        }

        ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_brunzip_filter_module;
        ctx->out_buf->recycled = 1;
        ctx->bufs++;

    } else {
        ctx->nomem = 1;
        return NGX_DECLINED;
    }

    ctx->next_out = ctx->out_buf->pos;
    ctx->available_out = conf->bufs.size;

    return NGX_OK;
}


static ngx_int_t
ngx_http_brunzip_filter_inflate(ngx_http_request_t *r,
    ngx_http_brunzip_ctx_t *ctx)
{
    int           rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "BrotliDecoderDecompressStream in: ni:%p no:%p ai:%ud ao:%ud fl:%d redo:%d",
                   ctx->next_in, ctx->next_out,
                   ctx->available_in, ctx->available_out,
                   ctx->flush, ctx->redo);

    rc = BrotliDecoderDecompressStream(ctx->bro, &ctx->available_in, (const uint8_t**)&ctx->next_in, &ctx->available_out, &ctx->next_out, &ctx->total_out);

    if (rc == BROTLI_DECODER_RESULT_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "BrotliDecoderDecompressStream() failed: %d, %d", ctx->flush, rc);
        return NGX_ERROR;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "BrotliDecoderDecompressStream out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   ctx->next_in, ctx->next_out,
                   ctx->available_in, ctx->available_out,
                   rc);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "brunzip in_buf:%p pos:%p",
                   ctx->in_buf, ctx->in_buf->pos);

    if (ctx->next_in) {
        ctx->in_buf->pos = ctx->next_in;

        if (ctx->available_in == 0) {
            ctx->next_in = NULL;
        }
    }

    ctx->out_buf->last = ctx->next_out;

    if (ctx->available_out == 0) {

        /* zlib wants to output some more data */

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ctx->out_buf;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        ctx->redo = 1;

        return NGX_AGAIN;
    }

    ctx->redo = 0;

    if (ctx->flush == FLUSH_FLUSH) {

        ctx->flush = FLUSH_PROCESS;

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = ctx->out_buf;

        if (ngx_buf_size(b) == 0) {

            b = ngx_calloc_buf(ctx->request->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

        } else {
            ctx->available_out = 0;
        }

        b->flush = 1;

        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return NGX_OK;
    }

    if (ctx->flush == FLUSH_FINISH && ctx->available_in == 0) {

        /*if (rc != Z_STREAM_END) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "inflate() returned %d on response end", rc);
            return NGX_ERROR;
        }*/

        if (ngx_http_brunzip_filter_inflate_end(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if (rc == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && ctx->available_in > 0) {
        ctx->redo = 1;

        return NGX_AGAIN;
    }

    if (ctx->in == NULL) {

        b = ctx->out_buf;

        if (ngx_buf_size(b) == 0) {
            return NGX_OK;
        }

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        ctx->available_out = 0;

        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return NGX_OK;
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_brunzip_filter_inflate_end(ngx_http_request_t *r,
    ngx_http_brunzip_ctx_t *ctx)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "brunzip inflate end");

    BrotliDecoderDestroyInstance(&ctx->bro);

    b = ctx->out_buf;

    if (ngx_buf_size(b) == 0) {

        b = ngx_calloc_buf(ctx->request->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    b->sync = 1;

    ctx->done = 1;

    return NGX_OK;
}


static void *
ngx_http_brunzip_filter_alloc(void *opaque, u_int items, u_int size)
{
    ngx_http_brunzip_ctx_t *ctx = opaque;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "brunzip alloc: n:%ud s:%ud",
                   items, size);

    return ngx_palloc(ctx->request->pool, items * size);
}


static void
ngx_http_brunzip_filter_free(void *opaque, void *address)
{
#if 0
    ngx_http_brunzip_ctx_t *ctx = opaque;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "brunzip free: %p", address);
#endif
}


static void *
ngx_http_brunzip_create_conf(ngx_conf_t *cf)
{
    ngx_http_brunzip_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_brunzip_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->bufs.num = 0;
     */

    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_brunzip_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_brunzip_conf_t *prev = parent;
    ngx_http_brunzip_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / ngx_pagesize, ngx_pagesize);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_brunzip_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_brunzip_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_brunzip_body_filter;

    return NGX_OK;
}