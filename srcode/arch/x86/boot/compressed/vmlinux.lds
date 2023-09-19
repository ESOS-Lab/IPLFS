OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(startup_64)
SECTIONS
{
 . = 0;
 .head.text : {
  _head = . ;
  KEEP(*(.head.text))
  _ehead = . ;
 }
 .rodata..compressed : {
  *(.rodata..compressed)
 }
 .text : {
  _text = .;
  *(.text)
  *(.text.*)
  _etext = . ;
 }
 .rodata : {
  _rodata = . ;
  *(.rodata)
  *(.rodata.*)
  _erodata = . ;
 }
 .data : {
  _data = . ;
  *(.data)
  *(.data.*)
  *(.bss.efistub)
  _edata = . ;
 }
 . = ALIGN((1 << (6)));
 .bss : {
  _bss = . ;
  *(.bss)
  *(.bss.*)
  *(COMMON)
  . = ALIGN(8);
  _ebss = .;
 }
       . = ALIGN((1 << 12));
       .pgtable : {
  _pgtable = . ;
  *(.pgtable)
  _epgtable = . ;
 }
 . = ALIGN((1 << 12));
 _end = .;
 .stab 0 : { *(.stab) } .stabstr 0 : { *(.stabstr) } .stab.excl 0 : { *(.stab.excl) } .stab.exclstr 0 : { *(.stab.exclstr) } .stab.index 0 : { *(.stab.index) } .stab.indexstr 0 : { *(.stab.indexstr) }
 .debug 0 : { *(.debug) } .line 0 : { *(.line) } .debug_srcinfo 0 : { *(.debug_srcinfo) } .debug_sfnames 0 : { *(.debug_sfnames) } .debug_aranges 0 : { *(.debug_aranges) } .debug_pubnames 0 : { *(.debug_pubnames) } .debug_info 0 : { *(.debug_info .gnu.linkonce.wi.*) } .debug_abbrev 0 : { *(.debug_abbrev) } .debug_line 0 : { *(.debug_line) } .debug_frame 0 : { *(.debug_frame) } .debug_str 0 : { *(.debug_str) } .debug_loc 0 : { *(.debug_loc) } .debug_macinfo 0 : { *(.debug_macinfo) } .debug_pubtypes 0 : { *(.debug_pubtypes) } .debug_ranges 0 : { *(.debug_ranges) } .debug_weaknames 0 : { *(.debug_weaknames) } .debug_funcnames 0 : { *(.debug_funcnames) } .debug_typenames 0 : { *(.debug_typenames) } .debug_varnames 0 : { *(.debug_varnames) } .debug_gnu_pubnames 0 : { *(.debug_gnu_pubnames) } .debug_gnu_pubtypes 0 : { *(.debug_gnu_pubtypes) } .debug_types 0 : { *(.debug_types) } .debug_macro 0 : { *(.debug_macro) } .debug_addr 0 : { *(.debug_addr) }
 .comment 0 : { *(.comment) } .symtab 0 : { *(.symtab) } .strtab 0 : { *(.strtab) } .shstrtab 0 : { *(.shstrtab) }
 /DISCARD/ : { *(.exit.text) *(.text.exit) *(.exit.data .exit.data.*) *(.fini_array .fini_array.*) *(.dtors .dtors.*) *(.exitcall.exit) *(.discard) *(.discard.*) *(.modinfo) *(.gnu.version*) }
 /DISCARD/ : {
  *(.dynamic) *(.dynsym) *(.dynstr) *(.dynbss)
  *(.hash) *(.gnu.hash)
  *(.note.*)
 }
 .got.plt (INFO) : {
  *(.got.plt)
 }
 ASSERT(SIZEOF(.got.plt) == 0 ||
        SIZEOF(.got.plt) == 0x18,
        "Unexpected GOT/PLT entries detected!")
 .got : {
  *(.got)
 }
 ASSERT(SIZEOF(.got) == 0, "Unexpected GOT entries detected!")
 .plt : {
  *(.plt) *(.plt.*)
 }
 ASSERT(SIZEOF(.plt) == 0, "Unexpected run-time procedure linkages detected!")
 .rel.dyn : {
  *(.rel.*) *(.rel_*)
 }
 ASSERT(SIZEOF(.rel.dyn) == 0, "Unexpected run-time relocations (.rel) detected!")
 .rela.dyn : {
  *(.rela.*) *(.rela_*)
 }
 ASSERT(SIZEOF(.rela.dyn) == 0, "Unexpected run-time relocations (.rela) detected!")
}
