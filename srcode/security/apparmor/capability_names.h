static const char *const capability_names[] = {
[0] = "chown",
[1] = "dac_override",
[2] = "dac_read_search",
[3] = "fowner",
[4] = "fsetid",
[5] = "kill",
[6] = "setgid",
[7] = "setuid",
[8] = "setpcap",
[9] = "linux_immutable",
[10] = "net_bind_service",
[11] = "net_broadcast",
[12] = "net_admin",
[13] = "net_raw",
[14] = "ipc_lock",
[15] = "ipc_owner",
[16] = "sys_module",
[17] = "sys_rawio",
[18] = "sys_chroot",
[19] = "sys_ptrace",
[20] = "sys_pacct",
[21] = "sys_admin",
[22] = "sys_boot",
[23] = "sys_nice",
[24] = "sys_resource",
[25] = "sys_time",
[26] = "sys_tty_config",
[27] = "mknod",
[28] = "lease",
[29] = "audit_write",
[30] = "audit_control",
[31] = "setfcap",
[32] = "mac_override",
[33] = "mac_admin",
[34] = "syslog",
[35] = "wake_alarm",
[36] = "block_suspend",
[37] = "audit_read",
[38] = "perfmon",
[39] = "bpf",
[40] = "checkpoint_restore",
};
#define AA_SFS_CAPS_MASK "chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease audit_write audit_control setfcap mac_override mac_admin syslog wake_alarm block_suspend audit_read perfmon bpf checkpoint_restore"
