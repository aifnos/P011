CC ?= cc
PKG_CONFIG ?= pkg-config
CFLAGS ?= -O2
CFLAGS += -std=c99 -Wall -Wextra -Werror -pedantic -D_FORTIFY_SOURCE=2 -fstack-protector-strong
GIO_CFLAGS := $(shell $(PKG_CONFIG) --cflags gio-2.0 gio-unix-2.0 glib-2.0)
GIO_LIBS := $(shell $(PKG_CONFIG) --libs gio-2.0 gio-unix-2.0 glib-2.0)

.PHONY: all test test-gatt test-wifi clean
all: mta-bluez-helper mta-wifi-caps
mta-wifi-caps: mta_wifi_caps.c mta_wifi_caps.h
	$(CC) $(CFLAGS) mta_wifi_caps.c -o $@
tests/test_wifi_caps: tests/test_wifi_caps.c mta_wifi_caps.c mta_wifi_caps.h
	$(CC) $(CFLAGS) -DMTA_WIFI_CAPS_NO_MAIN mta_wifi_caps.c tests/test_wifi_caps.c -o $@
test-wifi: tests/test_wifi_caps
	./tests/test_wifi_caps
mta-bluez-helper: mta_bluez_helper.c mta_core.c mta_core.h
	$(CC) $(CFLAGS) $(GIO_CFLAGS) mta_bluez_helper.c mta_core.c -o $@ $(GIO_LIBS)
tests/test_core: tests/test_core.c mta_core.c mta_core.h
	$(CC) $(CFLAGS) mta_core.c tests/test_core.c -o $@
test: tests/test_core
	./tests/test_core
tests/test_gatt: tests/test_gatt.c mta_bluez_helper.c mta_core.c mta_core.h
	$(CC) $(CFLAGS) $(GIO_CFLAGS) tests/test_gatt.c mta_core.c -o $@ $(GIO_LIBS)
test-gatt: tests/test_gatt
	./tests/test_gatt
clean:
	$(RM) mta-bluez-helper mta-wifi-caps tests/test_core tests/test_gatt tests/test_wifi_caps
