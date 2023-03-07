ifneq ("$(wildcard $(CURDIR)/mk/platform/$(SYSTEM).mk)", "")
	include $(CURDIR)/mk/platform/$(SYSTEM).mk
else
	include $(CURDIR)/mk/platform/linux.mk
endif

ifneq ($(OS), Windows_NT)
	include $(CURDIR)/mk/platform/unix_common.mk
endif
