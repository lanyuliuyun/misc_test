
TINYLIB_ROOT = /mnt/d/tinylib

dtls_bio: dtls_bio.c
	gcc $^ -o $@ -I$(TINYLIB_ROOT) -g -L$(TINYLIB_ROOT)/output -ltinylib \
        -I/usr/local/openssl/include \
        -L/usr/local/openssl/lib -lssl -lcrypto \
        -ldl -pthread \
        -DUSE_STREAM_BIO

tls_pipe: tls_pipe.c
	gcc $^ -o $@ -I$(TINYLIB_ROOT) -g -L$(TINYLIB_ROOT)/output -ltinylib -lssl