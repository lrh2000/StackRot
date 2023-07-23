ENTRY(_start)

SECTIONS
{
  . = 0x40000;

  __text_start = .;

  .text :
  {
    *(.text) *(.text.*)
    *(.rodata) *(.rodata.*)
  }

  __text_end = .;

  . = ALIGN(4096);

  __data_start = .;

  .data :
  {
    *(.data) *(.data.*)
    *(.bss) *(.bss.*)
  }

  __data_end = .;

  /DISCARD/ : { *(*) }
}
