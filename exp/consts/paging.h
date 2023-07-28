#pragma once

#define PAGE_SIZE	0x1000UL
#define PAGE_MASK	0x0fffUL
#define PAGE_ALIGN(val) (((val) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

#define TASK_SIZE 0x800000000000UL

#define LEAF_PAGES 512
