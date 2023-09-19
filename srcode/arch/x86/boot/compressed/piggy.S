.section ".rodata..compressed","a",@progbits
.globl z_input_len
z_input_len = 10261303
.globl z_output_len
z_output_len = 55644552
.globl input_data, input_data_end
input_data:
.incbin "arch/x86/boot/compressed/vmlinux.bin.gz"
input_data_end:
.section ".rodata","a",@progbits
.globl input_len
input_len:
	.long 10261303
.globl output_len
output_len:
	.long 55644552
