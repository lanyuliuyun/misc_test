
TINYLIB_ROOT = /mnt/d/tinylib

tls_pipe: tls_pipe.c
	gcc $^ -o $@ -I$(TINYLIB_ROOT) -g -L$(TINYLIB_ROOT)/output -ltinylib -lssl
