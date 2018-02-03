
TINYLIB_ROOT = /mnt/d/tinylib

ice_test: ice_test.c
	gcc $^ -o $@ \
        -g \
        -I$(TINYLIB_ROOT) -L$(TINYLIB_ROOT)/output/ -ltinylib \
        -lpj -lpjlib-util -lpjnath

turn: turn.c
	gcc $^ -o $@ \
        -g \
        -I$(TINYLIB_ROOT) -L$(TINYLIB_ROOT)/output/ -ltinylib \
        -lpj -lpjlib-util -lpjnath
