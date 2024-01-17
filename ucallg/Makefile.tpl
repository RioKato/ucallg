module := {{ module }}

ifneq ($(KERNELRELEASE),)
obj-m := $(module).o
CFLAGS_$(module).o += -std=gnu99

else
target := {{ target }}
module_ko := $(module).ko
module_c := $(module).c
module_h := $(module).h
module_ac := $(module).ac
module_toml := $(module).toml
module_ldd := $(module).ldd

.PHONY: all
all: $(module_ko)

$(module_ldd): $(target)
	{ echo $(realpath $<); ldd $< | grep -o '/\S*'; } | sed '/ld-linux/s/^/# /' > $@

.PHONY: ldd
ldd: $(module_ldd)

$(module_toml): $(module_ldd)
	cat $< | grep -v -e '^$$' -e '^\s*#' | while read -r lib; do \
		opt=$$(objdump -h "$$lib" | awk '($$2==".text"){ printf "-w 0x%s 0x%s",$$6,$$3 }'); \
		n2t="ucallg n2t $$opt $$lib"; \
		{ \
			echo "$$lib"; \
			if command -v debuginfod-find > /dev/null; then \
				debuginfod-find debuginfo "$$lib" 2> /dev/null; \
			fi; \
		} | grep -v '^$$' | while read -r lib; do \
			nm -C --defined-only --without-symbol-versions "$$lib"; \
			nm -D -C --defined-only --without-symbol-versions "$$lib"; \
		done 2> /dev/null | eval "$$n2t"; \
	done > $@

.PHONY: toml
toml: $(module_toml)

$(module_c): $(module_toml)
	ucallg src $<

$(module_h): $(if $(wildcard $(module_h)),,$(module_toml))
	ucallg config $<

.PHONY: config
config: $(module_h)

$(module_ac): $(if $(wildcard $(module_ac)),,$(module_ko))
	ucallg view -a -p $(shell pgrep $(target)) -l -s -c $(module)

.PHONY: autoconfig
autoconfig: $(module_ac)

.PHONY: view
view: $(module_ko)
	ucallg view -p $(shell pgrep $(target)) -l -s -c $(module)

$(module_ko): $(module_c) $(wildcard $(module_h)) $(wildcard $(module_ac))
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

.PHONY: clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

endif
