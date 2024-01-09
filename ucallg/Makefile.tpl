module := {{ module }}
module_c := $(module).c
module_cno := $(module).cno
module_h := $(module).h

ifneq ($(KERNELRELEASE),)

ifneq ($(shell command -v ccache),)
ifneq ($(wildcard $(M)/$(module_h)),)
CC := ccache $(CC)
endif
endif

obj-m := $(module).o
CFLAGS_$(module).o += -std=gnu99

define add_module_n
$(M)/$(module)_$(1).c:
	ln -s $(module_c) $$@
clean-files += $(module)_$(1).c
$(module)-y += $(module)_$(1).o
CFLAGS_$(module)_$(1).o += -std=gnu99
CFLAGS_$(module)_$(1).o += -D COMPILENO=$(1)
endef

$(foreach i,$(shell seq 0 $(file < $(M)/$(module_cno))),$(eval $(call add_module_n,$(i))))

else

target := {{ target }}
module_ko := $(module).ko
module_toml := $(module).toml
module_ldd := $(module).ldd

.PHONY: all
all: $(module_ko)

$(module_ldd): $(target)
	{ echo $(realpath $<); ldd $< | grep -o '/\S*'; } > $@

.PHONY: ldd
ldd: $(module_ldd)

$(module_toml): $(module_ldd)
	cat $< | grep -v '^$$' | while read -r lib; do \
		weak=$$(objdump -h "$$lib" | awk '($$2==".text"){ printf "-w 0x%s 0x%s",$$6,$$3 }'); \
		{ \
			echo "$$lib"; \
			if command -v debuginfod-find > /dev/null; then \
				debuginfod-find debuginfo "$$lib" 2> /dev/null; \
			fi; \
		} | grep -v '^$$' | while read -r line; do \
			nm -C --defined-only --without-symbol-versions "$$line"; \
			nm -D -C --defined-only --without-symbol-versions "$$line"; \
		done 2> /dev/null | ucallg n2t $$weak "$$lib"; \
	done > $@

.PHONY: toml
toml: $(module_toml)

$(module_c): $(module_toml)
	ucallg src $<

$(module_cno): $(module_toml)
	ucallg cno $<

$(module_h): $(module_toml)
	ucallg conf $<

.PHONY: conf
conf: $(module_h)

$(module_ko): $(module_c) $(module_cno) $(wildcard $(module_h))
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

.PHONY: view
view: $(module_ko)
	ucallg view -p $(shell pgrep $(target)) -l -s -c $(module)

.PHONY: clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

endif
