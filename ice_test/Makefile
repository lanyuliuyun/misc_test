
TINYLIB_ROOT = /mnt/d/tinylib
CUBIE_ROOT = /mnt/d/cubieboard/local

#-DUSE_ICE_HOST -DUSE_ICE_SVRFLX -DUSE_ICE_RELAY

ice_test: ice_test.c
	gcc $^ -o $@ \
        -g \
        -I$(TINYLIB_ROOT) -L$(TINYLIB_ROOT)/output/ -ltinylib_x64 \
        -lpj -lpjlib-util -lpjnath -pthread \
        -DUSE_ICE_SVRFLX

ice_test_arm: ice_test.c
	arm-sunxiA20-linux-gnueabi-gcc $^ -o $@ \
        -g \
        -I$(TINYLIB_ROOT) -L$(TINYLIB_ROOT)/output/ -ltinylib_arm \
        -I$(CUBIE_ROOT)/include -L$(CUBIE_ROOT)/lib \
        -DPJ_IS_LITTLE_ENDIAN=1 -DPJ_IS_BIG_ENDIAN=0 \
        -lpj -lpjlib-util -lpjnath -pthread \
        -DUSE_ICE_SVRFLX

turn: turn.c
	gcc $^ -o $@ \
        -g \
        -I$(TINYLIB_ROOT) -L$(TINYLIB_ROOT)/output/ -ltinylib \
        -lpj -lpjlib-util -lpjnath
