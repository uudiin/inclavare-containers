# src/enclave-quotes/ecdsaquote
#
# [IN,OPTIONAL] Topdir: specify the location of enclave-tls source code tree

Topdir ?= $(shell readlink -f ../../..)

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif
CFLAGS += -I$(Topdir)/samples/sgx-stub-enclave

ifdef OCCLUM
  Enclave_Tls_Ldflags += -L/opt/intel/sgxsgk/lib64 -lsgx_dcap_quoteverify
endif

Enclave_Tls_Instance_Name := sgx-ecdsa-qve
Enclave_Tls_Instance_Type := enclave-quote
include $(Topdir)/rules/sgx_env.mk

include $(Topdir)/rules/wolfssl_env.mk
include $(Topdir)/rules/instance.mk
include $(Topdir)/rules/sgx_rules.mk

ifneq ($(__Build_Rules_Imported),1)
  include $(Topdir)/rules/build_rules.mk
endif
