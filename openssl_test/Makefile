
TINYLIB_ROOT = /mnt/d/tinylib

dtls_srtp_bio: dtls_srtp_bio.c
	gcc $^ -o $@ -I$(TINYLIB_ROOT) -g -L$(TINYLIB_ROOT)/output -ltinylib_x64 \
        -lssl -lcrypto \
        -ldl -pthread -lsrtp2

dtls_srtp: dtls_srtp.c
	gcc $^ -o $@ -I$(TINYLIB_ROOT) -g -L$(TINYLIB_ROOT)/output -ltinylib_x64 \
        -lssl -lcrypto \
        -ldl -pthread -lsrtp2

dtls_bio: dtls_bio.c
	gcc $^ -o $@ \
        -I$(TINYLIB_ROOT) -g -L$(TINYLIB_ROOT)/output -ltinylib_x64 \
        -lssl -lcrypto \
        -ldl -pthread \
        -DUSE_STREAM_BIO

tls_pipe: tls_pipe.c
	gcc $^ -o $@ \
        -g \
        -I$(TINYLIB_ROOT) -L$(TINYLIB_ROOT)/output -ltinylib_x64 \
        -lssl -lcrypto \
        -ldl -pthread
