dirs := nullcrypto wolfcrypt wolfcrypt-sgx opencrypt
all clean install uninstall:
	for d in $(dirs); do \
	  make -C $$d $@; \
	done
