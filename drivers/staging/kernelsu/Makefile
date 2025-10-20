kernelsu-objs := ksu.o
kernelsu-objs += allowlist.o
kernelsu-objs += apk_sign.o
kernelsu-objs += sucompat.o
kernelsu-objs += throne_tracker.o
kernelsu-objs += core_hook.o
kernelsu-objs += ksud.o
kernelsu-objs += embed_ksud.o
kernelsu-objs += kernel_compat.o

kernelsu-objs += selinux/selinux.o
kernelsu-objs += selinux/sepolicy.o
kernelsu-objs += selinux/rules.o
ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/uapi/asm-generic/errno.h

obj-$(CONFIG_KSU) += kernelsu.o

$(eval KSU_VERSION=12069)
$(info -- KernelSU version: $(KSU_VERSION))
ccflags-y += -DKSU_VERSION=$(KSU_VERSION)

ifeq ($(shell grep -q " current_sid(void)" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_CURRENT_SID
endif

ifeq ($(shell grep -q "struct selinux_state " $(srctree)/security/selinux/include/security.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_SELINUX_STATE
endif

# tiann/KernelSU
KSU_EXPECTED_SIZE := 0x033b
KSU_EXPECTED_HASH := c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6

# rsuntk/KernelSU
KSU_EXPECTED_SIZE_CUST := 0x396
KSU_EXPECTED_HASH_CUST := f415f4ed9435427e1fdf7f1fccd4dbc07b3d6b8751e4dbcec6f19671f427870b

# ShirkNeko/SukiSU-Ultra
KSU_EXPECTED_SIZE_CUST1 := 0x35c
KSU_EXPECTED_HASH_CUST1 := 947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef

# Wild/WildKSU
KSU_EXPECTED_SIZE_CUST2 := 0x39b
KSU_EXPECTED_HASH_CUST2 := 593d4ce870c02468639efeef631e07ca4d852d63f154be56706229f9a5be0800

ifdef KSU_MANAGER_PACKAGE
ccflags-y += -DKSU_MANAGER_PACKAGE=\"$(KSU_MANAGER_PACKAGE)\"
$(info -- KernelSU Manager package name: $(KSU_MANAGER_PACKAGE))
endif

$(info -- Official KernelSU Manager signature size: $(KSU_EXPECTED_SIZE))
$(info -- Official KernelSU Manager signature hash: $(KSU_EXPECTED_HASH))
$(info -- Unofficial KernelSU Manager signature size: $(KSU_EXPECTED_SIZE_CUST))
$(info -- Unofficial KernelSU Manager signature hash: $(KSU_EXPECTED_HASH_CUST))
$(info -- SukiSU-Ulta Manager signature size: $(KSU_EXPECTED_SIZE_CUST1))
$(info -- SukiSU-Ulta Manager signature hash: $(KSU_EXPECTED_HASH_CUST1))
$(info -- WildKSU Manager signature size: $(KSU_EXPECTED_SIZE_CUST2))
$(info -- WildKSU Manager signature hash: $(KSU_EXPECTED_HASH_CUST2))

ccflags-y += -DEXPECTED_SIZE=$(KSU_EXPECTED_SIZE)
ccflags-y += -DEXPECTED_HASH=\"$(KSU_EXPECTED_HASH)\"
ccflags-y += -DEXPECTED_SIZE_CUST=$(KSU_EXPECTED_SIZE_CUST)
ccflags-y += -DEXPECTED_HASH_CUST=\"$(KSU_EXPECTED_HASH_CUST)\"
ccflags-y += -DEXPECTED_SIZE_CUST1=$(KSU_EXPECTED_SIZE_CUST1)
ccflags-y += -DEXPECTED_HASH_CUST1=\"$(KSU_EXPECTED_HASH_CUST1)\"
ccflags-y += -DEXPECTED_SIZE_CUST2=$(KSU_EXPECTED_SIZE_CUST2)
ccflags-y += -DEXPECTED_HASH_CUST2=\"$(KSU_EXPECTED_HASH_CUST2)\"

# UL, look for "ext4_unregister_sysfs" on fs/ext4
ifeq ($(shell grep -q "^extern void ext4_unregister_sysfs" $(srctree)/fs/ext4/ext4.h 2>/dev/null; echo $$?),0)
ccflags-y += -DKSU_HAS_MODERN_EXT4
endif

# enable functions that use stuct filename when ksu_handle_execveat is found
ifeq ($(shell grep -q "ksu_handle_execveat" $(srctree)/fs/exec.c; echo $$?),0)
ccflags-y += -DKSU_USE_STRUCT_FILENAME
endif

ifeq ($(shell grep -q "ksu_handle_execveat" $(srctree)/arch/arm/kernel/sys_arm.c; echo $$?),0)
ccflags-y += -DKSU_USE_STRUCT_FILENAME
endif

ifneq ($(shell grep -q "get_cred_rcu" $(srctree)/include/linux/cred.h; echo $$?),0)
$(error You must backport get_cred_rcu - https://github.com/tiann/KernelSU/pull/2320#issuecomment-2564232958 )
endif

ifeq ($(shell grep -q "int path_umount" $(srctree)/fs/namespace.c; echo $$?),0)
$(info -- KernelSU/compat: path_umount found)
ccflags-y += -DKSU_HAS_PATH_UMOUNT
endif

ifeq ($(shell grep -q "strncpy_from_user_nofault" $(srctree)/include/linux/uaccess.h; echo $$?),0)
$(info -- KernelSU/compat: strncpy_from_user_nofault found)
ccflags-y += -DKSU_STRNCPY_FROM_USER_NOFAULT
endif

ifeq ($(shell grep -q "strncpy_from_unsafe_user" $(srctree)/include/linux/uaccess.h; echo $$?),0)
$(info -- KernelSU/compat: strncpy_from_unsafe_user found)
ccflags-y += -DKSU_STRNCPY_FROM_UNSAFE_USER
endif

ifeq ($(shell grep -q "ssize_t kernel_read" $(srctree)/fs/read_write.c; echo $$?),0)
$(info -- KernelSU/compat: newer kernel_read found)
ccflags-y += -DKSU_NEW_KERNEL_READ
endif

ifeq ($(shell grep "ssize_t kernel_write" $(srctree)/fs/read_write.c | grep -q "const void" ; echo $$?),0)
$(info -- KernelSU/compat: newer kernel_write found)
ccflags-y += -DKSU_NEW_KERNEL_WRITE
endif

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function

# Keep a new line here!! Because someone may append config
