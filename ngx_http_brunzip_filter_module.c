/*
 * Copyright (C) Mathew Heard (https://www.x4b.net)
 * 
 * Includes work from nginx gunzip module:
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <brotli/decode.h>

typedef struct {
    ngx_flag_t           enable;
    ngx_bufs_t           bufs;
} ngx_http_brunzip_conf_t;

typedef enum {
	FLUSH_NOFLUSH = 0,
	FLUSH_FLUSH = 1,
	FLUSH_FINISH = 2
} BrotliFlushStates;

typedef struct {
    // chain of buffers input (not owned by us)
    ngx_chain_t         *in;

    // free buffers (owned by us) that can become output buffers
    ngx_chain_t         *free;

    // buffers sent to next chains, waiting for consumption
    ngx_chain_t         *busy;

    // the current output chain
    ngx_chain_t         *out;

    // pointer to the last chain (link).
    // This is the newest chunk of data to be processed and the latest data
    ngx_chain_t        **last_out;

    // Current input buffer
    ngx_buf_t           *in_buf;

    // Current output buffer
    ngx_buf_t           *out_buf;

    // Number of buffers we currently have in use
    ngx_int_t            bufs;

    // Brotli decoder instance
    BrotliDecoderState   *bro;
	
    // Current brotli decompressor integration state
    uint8_t             *input;
    uint8_t             *output;
    uint8_t             *next_in;
    uint8_t             *next_out;
    size_t               available_in;
    size_t               available_out;
	size_t               total_out;
	
    // State flags
    BrotliFlushStates    flush:2;
    unsigned             started:1;
    unsigned             redo:1;
    unsigned             done:1;
    unsigned             nomem:1;

    // The current http request
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

/*
Look for "br,", "br;" or "br ", returns NGX_OK if found NGX_DECLINED otherwise
*/
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

    // If not enabled, not brotli, onto next header
    if (!conf->enable
        || r->headers_out.content_encoding == NULL
        || r->headers_out.content_encoding->value.len != 2
        || ngx_strncasecmp(r->headers_out.content_encoding->value.data, (u_char *) "br", 2) != 0)
    {
        return ngx_http_next_header_filter(r);
    }

    // If client accepts brotli
	if (accept_br(r->headers_in.accept_encoding) == NGX_OK) {
		return ngx_http_next_header_filter(r);
	}

    // We are doing this, so allocate a context
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_brunzip_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_brunzip_filter_module);
    ctx->request = r;

    // needed?
    r->filter_need_in_memory = 1;

    // We will be changing the content-encoding
    r->headers_out.content_encoding->hash = 0;
    r->headers_out.content_encoding = NULL;

    // All of these will change
    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    // On we go
    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_brunzip_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                     rc;
    ngx_uint_t              flush;
    ngx_chain_t            *cl;
    ngx_http_brunzip_ctx_t  *ctx;

    // Continue if not enabled (ctx == NULL) or done
    ctx = ngx_http_get_module_ctx(r, ngx_http_brunzip_filter_module);
    if (ctx == NULL || ctx->done) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http brunzip filter");

    // Initialize brotli & init context request state
    if (!ctx->started) {
        if (ngx_http_brunzip_filter_inflate_start(r, ctx) != NGX_OK) {
            goto failed;
        }
    }

    // Add the supplied chain to our input chain
    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            goto failed;
        }
    }

    // If there is no available output buffers ngx_http_brunzip_filter_get_buf will set ctx->nomem
    if (ctx->nomem) {
        // Pass onto next filters
        if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
            goto failed;
        }

        cl = NULL;

        // Look for consumed buffers (from busy chain) and return to free
        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (ngx_buf_tag_t) &ngx_http_brunzip_filter_module);

        // We have done the flush (but couldn't ngx_chain_update_chains have found nothing ??? )
        ctx->nomem = 0;
        flush = 0;

    } else {
        // If we have busy buffers - they need to be flushed before we can continue.
        flush = ctx->busy ? 1 : 0;
    }

    // Cycle while we can write to a client
    for ( ;; ) {

        // Cycle while there is data to feed zlib and
        for ( ;; ) {
            // Add another buffer from input into our ctx (if we want it)
            rc = ngx_http_brunzip_filter_add_data(r, ctx);
            if (rc == NGX_DECLINED) {
                // There is no more data for us
                break;
            }
            if (rc == NGX_AGAIN) {
                // We need to try again
                continue;
            }
            // rc == NGX_OK: we got some more data


            // Get us an output buffer
            rc = ngx_http_brunzip_filter_get_buf(r, ctx);
            if (rc == NGX_DECLINED) {
                // All our buffers are full
                // AKA ctx->nomem == 1
                break;
            }
            if (rc == NGX_ERROR) {
                // OOM during allocation of a new buffer
                goto failed;
            }

            // Do work
            rc = ngx_http_brunzip_filter_inflate(r, ctx);
            if (rc == NGX_OK) {
                // We have done work, break here as there is data to output
                break;
            }
            if (rc == NGX_ERROR) {
                // An error occurred. We will have to abort.
                goto failed;
            }
            // rc == NGX_AGAIN: Brotli wants more output buffer space
        }

        // ???
        if (ctx->out == NULL && !flush) {
            return ctx->busy ? NGX_AGAIN : NGX_OK;
        }

        // Send output chain to next filter
        rc = ngx_http_next_body_filter(r, ctx->out);
        if (rc == NGX_ERROR) {
            goto failed;
        }

        // Recover (ex-busy) buffers consumed by later filters and return them to free
        // Consumed buffers from out becomes busy as it's been sent to next chain (how ???)
        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (ngx_buf_tag_t) &ngx_http_brunzip_filter_module);

        // last output buffer out may have changed (become NULL) if we sent all buffers on (???).
        ctx->last_out = &ctx->out;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "brunzip out: %p", ctx->out);

        // We have done work, there may be more output space available (always ???)
        ctx->nomem = 0;
        flush = 0;

        // Inflate completed, we are done here. Pass along status code from next filter.
        if (ctx->done) {
            return rc;
        }
    }

    /* unreachable */

failed:
    // Done but not the way we wanted
    ctx->done = 1;

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_brunzip_filter_inflate_start(ngx_http_request_t *r,
    ngx_http_brunzip_ctx_t *ctx)
{
    ctx->bro = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (ctx->bro == NULL) {
        return NGX_ERROR;
	}
    
    ctx->started = 1;

    ctx->last_out = &ctx->out;
    ctx->input = NULL;
    ctx->output = NULL;
    ctx->next_in = NULL;
    ctx->next_out = NULL;
    ctx->available_in = 0;
    ctx->available_out = 0;
    ctx->total_out = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_brunzip_filter_add_data(ngx_http_request_t *r,
    ngx_http_brunzip_ctx_t *ctx)
{
    // Don't add more data if:
    // 1.   If there is currently available data in our context
    // 2.1. FLUSH_FLUSH: We will feed this buffer through the decompressor first before proceeding
    // 2.2. FLUSH_FINISH: The last buffer was marked as the final buffer for this request
    // 3.   We need to loop in order to output more data (redo)
    if (ctx->available_in || ctx->flush != FLUSH_NOFLUSH || ctx->redo) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "brunzip in: %p", ctx->in);

    // We are input limited, the previous filter has not outputted a buffer for us (yet)
    if (ctx->in == NULL) {
        return NGX_DECLINED;
    }

    // Take the next buffer from the input chain
    ctx->in_buf = ctx->in->buf;
    ctx->in = ctx->in->next;

    // Where we will start, and available bytes
    ctx->next_in = ctx->in_buf->pos;
    ctx->available_in = ctx->in_buf->last - ctx->in_buf->pos;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "brunzip in_buf:%p ni:%p ai:%ud",
                   ctx->in_buf,
                   ctx->next_in, ctx->available_in);

    if (ctx->in_buf->last_buf || ctx->in_buf->last_in_chain) {
        // This is the end, finally
        ctx->flush = FLUSH_FINISH;
    } else if (ctx->in_buf->flush) {
        // flush was requested
        ctx->flush = FLUSH_FLUSH;
    } else if (ctx->available_in == 0) {
        // We need more data
        ctx->flush = FLUSH_NOFLUSH;
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_brunzip_filter_get_buf(ngx_http_request_t *r,
    ngx_http_brunzip_ctx_t *ctx)
{
    ngx_http_brunzip_conf_t  *conf;

    // If Brotli does not want to output anything currently then we don't 
    // actually have to provide it with an output buffer, we will however
    // cycle and likely need to provide one then.
    if (ctx->available_out == 0) {
        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brunzip_filter_module);

    if (ctx->free) {
        // If we have free buffers take a buffer from the free chain and use that
        // as the output buffer
        ctx->out_buf = ctx->free->buf;
        ctx->free = ctx->free->next;

        // We don't need this to be flushed (???)
        ctx->out_buf->flush = 0;
    } else if (ctx->bufs < conf->bufs.num) {
        // There isn't any free buffers, but we are less than our limit
        // Therefore allocate a new buffer and make that our output buffer
        ctx->out_buf = ngx_create_temp_buf(r->pool, conf->bufs.size);
        if (ctx->out_buf == NULL) {
            return NGX_ERROR;
        }

        // This is ours, and we recycle
        ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_brunzip_filter_module;
        ctx->out_buf->recycled = 1;

        // Increase count towards limit
        ctx->bufs++;

    } else {
        // Over Limit, refuse to allocate
        ctx->nomem = 1;
        return NGX_DECLINED;
    }

    // The next output will be at the start of the new buffer & the remaining size the length
    ctx->next_out = ctx->out_buf->pos;
    ctx->available_out = conf->bufs.size;

    // A new buffer was allocated / recycled
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

    // Run decompressor
    // (brotliObj, [in, out] number of available input bytes, [in, out] ptr to input, [in, out] number of available output bytes, [in, out] ptr to output, [out] number of bytes written)
    rc = BrotliDecoderDecompressStream(ctx->bro, &ctx->available_in, (const uint8_t**)&ctx->next_in, &ctx->available_out, &ctx->next_out, &ctx->total_out);

    // Decoding error
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

    // If there is any data remaining
    if (ctx->next_in) {
        // Move input buffer forward by the amount consumed
		ctx->in_buf->pos = ctx->next_in;

        // If we consumed it all
        if (ctx->available_in == 0) {
            ctx->next_in = NULL;
        }
    }

    // We will start outputing into this chain from here next time
    ctx->out_buf->last = ctx->next_out;

    // brotli wants to output some more data, we will come back with a fresh buffer
    if (rc == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {

        // Create a chain with our output buffer
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

    // We where asked to flush this buffer, so we will
    if (ctx->flush == FLUSH_FLUSH) {
        // Buffer has been fed to the decompressor, we can now go back to feeding the context
        // with new input
        ctx->flush = FLUSH_NOFLUSH;

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = ctx->out_buf;

        if (ngx_buf_size(b) == 0) {
            // If resulting length was 0 then allocate a 0 length buffer
            // This will act as flush up until now

            b = ngx_calloc_buf(ctx->request->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }
        } else {
            // This buffer is now 'full' as we are sending it off at current capacity
            ctx->available_out = 0;
        }

        // Pass on the message to flush to next chain
        b->flush = 1;

        // Fill out the chain link
        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return NGX_OK;
    }

    // TODO: how can we be sure we end up here, and hence cleanining up the Brotli context
    if (ctx->flush == FLUSH_FINISH && ctx->available_in == 0) {
        // This should have been the end, but it wasn't. Error and more output cases are already handled above.
        if (rc == BROTLI_DECODER_NEEDS_MORE_INPUT) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "BrotliDecoderDecompressStream() did not reach end");
            return NGX_ERROR;
        }

        // Cleanup
        if (ngx_http_brunzip_filter_inflate_end(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    // rc == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT: Brotli has it's own buffer, so it will always consume all input bytes (NGX_AGAIN)
    // gunzip had to support more complex behaviour ???

    // ???
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

    // We will feed more data
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

    BrotliDecoderDestroyInstance(ctx->bro);

    // ???
    b = ctx->out_buf;
    if (ngx_buf_size(b) == 0) {
        b = ngx_calloc_buf(ctx->request->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }
    }

    // ???
    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    // ???
    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    // ???
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    b->sync = 1;

    // We are done, pass all buffers onto the next filter
    ctx->done = 1;

    return NGX_OK;
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