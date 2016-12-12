# ngx_brunzip_module

This NGINX module enables the brunzip decompression for Accept-Encoding:"br".

Brotli is a recent compression format developed by Google.

https://tools.ietf.org/html/rfc7932

Use the "--add-module=" when configuring NGINX to enable the module.

Config options:

brunzip on/off   - enable the module. When brotli is enabled, it takes
                  precendence over gzip if Accept-Encoding has both gzip and
                  brotli.
brunzip_buffers  num num - same as gunzip_buffers

Currently tested only on Linux.
