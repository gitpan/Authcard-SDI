/* $Id: sdi.h,v 1.3 1998/06/08 15:31:17 cvs Exp $
 *
 * Copyright (c) 1998 Nigel Metheringham. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the same terms as Perl itself.
 *
 * prototypes for all SecurID API Calls
 *
 * Reproduced from API Manual for v1.3
 *
 */

#include "sdi_defs.h"
#include "sdi_athd.h"
#include "sdacmvls.h"
#include "sdconf.h"

int creadcfg(void);
int sd_init(struct SD_CLIENT *sd);
int sd_auth(struct SD_CLIENT *sd);
int sd_check(char *passcode, char *username, struct SD_CLIENT *sd);
int sd_next(char *nextcode, struct SD_CLIENT *sd);
int sd_pin(char *pin, char cancelled, struct SD_CLIENT *sd);
void sd_close(void);
