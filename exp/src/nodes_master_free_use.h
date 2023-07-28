#pragma once

#define HEALTHCHECK_INIT 0
#define HEALTHCHECK_FREE 1
#define HEALTHCHECK_DONE 2

static _Atomic int healthcheck_state;
