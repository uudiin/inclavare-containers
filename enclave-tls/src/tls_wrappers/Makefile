dirs := nulltls openssl wolfssl wolfssl-sgx
all clean install uninstall:
	for d in $(dirs); do \
	  make -C $$d $@; \
	done
