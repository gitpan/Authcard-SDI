/* $Id: SDI.xs,v 1.25 1998/06/08 15:31:17 cvs Exp $ */

/*
 * Copyright (c) 1998 Nigel Metheringham. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the same terms as Perl itself.
 */

#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "sdi.h"

/* Nasty global bits needed... */
union config_record configure;
static char config_ok = 0;


typedef struct SD_CLIENT Authcard_SDI;


/* Constants used by i/f */
static int
not_here(s)
char *s;
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

static int
constant(name, arg)
char *name;
int arg;
{
  errno = 0;
  if (strnEQ(name, "ACM_", 4)) {
    switch(name[4]) {
    case 'A':
      if (strEQ(name, "ACM_ACCESS_DENIED"))
#ifdef ACM_ACCESS_DENIED
	return ACM_ACCESS_DENIED;
#else
      goto not_there;
#endif
      break;

    case 'E':
      if (strEQ(name, "ACM_ENTRY_ERR"))
#ifdef ACM_ENTRY_ERR
	return ACM_ENTRY_ERR;
#else
      goto not_there;
#endif
      break;

    case 'L':
      if (strEQ(name, "ACM_LOG_ACK"))
#ifdef ACM_LOG_ACK
	return ACM_LOG_ACK;
#else
      goto not_there;
#endif
      break;

    case 'N':
      if (strEQ(name, "ACM_NEW_PIN_ACCEPTED"))
#ifdef ACM_NEW_PIN_ACCEPTED
	return ACM_NEW_PIN_ACCEPTED;
#else
      goto not_there;
#endif
      if (strEQ(name, "ACM_NEW_PIN_REJECTED"))
#ifdef ACM_NEW_PIN_REJECTED
	return ACM_NEW_PIN_REJECTED;
#else
      goto not_there;
#endif
      if (strEQ(name, "ACM_NEW_PIN_REQUIRED"))
#ifdef ACM_NEW_PIN_REQUIRED
	return ACM_NEW_PIN_REQUIRED;
#else
      goto not_there;
#endif
      if (strEQ(name, "ACM_NEXT_CODE_BAD"))
#ifdef ACM_NEXT_CODE_BAD
	return ACM_NEXT_CODE_BAD;
#else
      goto not_there;
#endif
      if (strEQ(name, "ACM_NEXT_CODE_OK"))
#ifdef ACM_NEXT_CODE_OK
	return ACM_NEXT_CODE_OK;
#else
      goto not_there;
#endif
      if (strEQ(name, "ACM_NEXT_CODE_REQUIRED"))
#ifdef ACM_NEXT_CODE_REQUIRED
	return ACM_NEXT_CODE_REQUIRED;
#else
      goto not_there;
#endif
      break;

    case 'O':
      if (strEQ(name, "ACM_OK"))
#ifdef ACM_OK
	return ACM_OK;
#else
      goto not_there;
#endif
      break;

    case 'P':
      if (strEQ(name, "ACM_PC_BAD"))
#ifdef ACM_PC_BAD
	return ACM_PC_BAD;
#else
      goto not_there;
#endif
      if (strEQ(name, "ACM_PC_OK"))
#ifdef ACM_PC_OK
	return ACM_PC_OK;
#else
      goto not_there;
#endif
      break;

    case 'S':
      if (strEQ(name, "ACM_SHELL_BAD"))
#ifdef ACM_SHELL_BAD
	return ACM_SHELL_BAD;
#else
      goto not_there;
#endif
      if (strEQ(name, "ACM_SHELL_OK"))
#ifdef ACM_SHELL_OK
	return ACM_SHELL_OK;
#else
      goto not_there;
#endif
      if (strEQ(name, "ACM_SUSPECT_ACK"))
#ifdef ACM_SUSPECT_ACK
	return ACM_SUSPECT_ACK;
#else
      goto not_there;
#endif
      break;

    case 'T':
      if (strEQ(name, "ACM_TIME_OK"))
#ifdef ACM_TIME_OK
	return ACM_TIME_OK;
#else
      goto not_there;
#endif
      break;

    default:
      break;
    }
  }
  errno = EINVAL;
  return 0;

 not_there:
  errno = ENOENT;
  return 0;
}

#ifdef __cplusplus
}
#endif



MODULE = Authcard::SDI		PACKAGE = Authcard::SDI		

PROTOTYPES: ENABLE

Authcard_SDI * 
new(CLASS = "Authcard::SDI")
     char * CLASS

  CODE:
     {
       if (!config_ok) {
	 if (creadcfg()) {
	   /* Need to fail here.... */
	   warn("unable to get SDI config");
	   XSRETURN_UNDEF;
	 } else {
	   config_ok++;
	 }
       }
       if (config_ok) {
	 RETVAL = (Authcard_SDI *)safemalloc(sizeof(Authcard_SDI));
	 if( RETVAL == NULL ){
	   warn("unable to malloc SD_CLIENT data block");
	   XSRETURN_UNDEF;
	 }
	 memset(RETVAL, 0, sizeof(Authcard_SDI));
	 if (sd_init((Authcard_SDI *) RETVAL)) {
	   safefree((char *) RETVAL);
	   warn("unable to init SD_CLIENT data block");
	   XSRETURN_UNDEF;
	 }
       }
     }

  OUTPUT:
    RETVAL

void
DESTROY(context)
     Authcard_SDI * context

  CODE:
     {
       sd_close();
       safefree((char *) context);
     }


int
auth(self, user = NULL)
     Authcard_SDI *      self
     char *              user

  CODE:
    if (user && *user) {
      strncpy(self->username, user, LENACMNAME);
      self->username[LENACMNAME - 1] = '\0';
    }
    RETVAL = sd_auth(self);

  OUTPUT:
    RETVAL


int
check(self, passcode, username)
        Authcard_SDI *      self
        char *  passcode
        char *  username

  CODE:
     {
       RETVAL = sd_check(passcode, username, self);
     }

  OUTPUT:
    RETVAL


int
next(self, nextcode)
        Authcard_SDI *      self
        char *  nextcode

  CODE:
     {
       RETVAL = sd_next(nextcode, self);
     }

  OUTPUT:
    RETVAL


int
pin(self, pin, cancelled = 0)
        Authcard_SDI *      self
        char *  pin
        char  cancelled

  CODE:
     {
       RETVAL = sd_pin(pin, cancelled ? 1 : 0, self);
     }

  OUTPUT:
    RETVAL


char *
shell(self)
        Authcard_SDI *      self

  CODE:
    RETVAL = self->shell;

  OUTPUT:
    RETVAL

char *
system_pin(self)
        Authcard_SDI *      self

  CODE:
    RETVAL = self->system_pin;

  OUTPUT:
    RETVAL

int
min_pin_len(self)
        Authcard_SDI *      self

  CODE:
    RETVAL = self->min_pin_len;

  OUTPUT:
    RETVAL

int
max_pin_len(self)
        Authcard_SDI *      self

  CODE:
    RETVAL = self->max_pin_len;

  OUTPUT:
    RETVAL

int
fixed_pin_size(self)
        Authcard_SDI *      self

  CODE:
    RETVAL = self->fixed_pin_size;

  OUTPUT:
    RETVAL

int
user_selectable(self)
        Authcard_SDI *      self

  CODE:
    RETVAL = self->user_selectable;

  OUTPUT:
    RETVAL


int
alphanumeric(self)
        Authcard_SDI *      self

  CODE:
    RETVAL = self->alphanumeric;

  OUTPUT:
    RETVAL


int
timeout(self)
        Authcard_SDI *      self

  CODE:
    RETVAL = self->timeout;

  OUTPUT:
    RETVAL


int
time_delta(self)
        Authcard_SDI *      self

  CODE:
    RETVAL = self->time_delta;

  OUTPUT:
    RETVAL


char *
username(self, newuser = NULL)
        Authcard_SDI *      self
        char *		    newuser

  CODE:
    if (newuser) {
      strncpy(self->username, newuser, LENACMNAME);
      self->username[LENACMNAME - 1] = '\0';
    }
    RETVAL = self->username;

  OUTPUT:
    RETVAL


char *
validated_passcode(self)
        Authcard_SDI *      self

  CODE:
    RETVAL = self->validated_passcode;

  OUTPUT:
    RETVAL


char *
protectdir(self)
        Authcard_SDI *      self

  CODE:
    RETVAL = self->protectdir;

  OUTPUT:
    RETVAL


int
application_id(self)
        Authcard_SDI *      self

  CODE:
    RETVAL = self->application_id;

  OUTPUT:
    RETVAL


int
passcode_time(self)
        Authcard_SDI *      self

  CODE:
    RETVAL = self->passcode_time;

  OUTPUT:
    RETVAL


int
release_code(self)
        Authcard_SDI *      self

  CODE:
    RETVAL = self->release_code;

  OUTPUT:
    RETVAL


int
constant(name,arg)
        char *          name
        int             arg

  CODE:
    RETVAL = constant(name,arg);

  OUTPUT:
    RETVAL

char *
_constant_name(retcode)
        int             retcode;

  CODE:
    switch(retcode) {
    case ACM_ACCESS_DENIED:
      RETVAL = "ACM_ACCESS_DENIED";
      break;
    case ACM_ENTRY_ERR:
      RETVAL = "ACM_ENTRY_ERR";
      break;
    case ACM_LOG_ACK:
      RETVAL = "ACM_LOG_ACK";
      break;
    case ACM_NEW_PIN_ACCEPTED:
      RETVAL = "ACM_NEW_PIN_ACCEPTED";
      break;
    case ACM_NEW_PIN_REJECTED:
      RETVAL = "ACM_NEW_PIN_REJECTED";
      break;
    case ACM_NEW_PIN_REQUIRED:
      RETVAL = "ACM_NEW_PIN_REQUIRED";
      break;
    case ACM_NEXT_CODE_BAD:
      RETVAL = "ACM_NEXT_CODE_BAD";
      break;
    case ACM_NEXT_CODE_OK:
      RETVAL = "ACM_NEXT_CODE_OK";
      break;
    case ACM_NEXT_CODE_REQUIRED:
      RETVAL = "ACM_NEXT_CODE_REQUIRED";
      break;
    case ACM_OK:
      RETVAL = "ACM_OK";
      break;
    case ACM_PC_BAD:
      RETVAL = "ACM_PC_BAD";
      break;
    case ACM_PC_OK:
      RETVAL = "ACM_PC_OK";
      break;
    case ACM_SHELL_BAD:
      RETVAL = "ACM_SHELL_BAD";
      break;
    case ACM_SHELL_OK:
      RETVAL = "ACM_SHELL_OK";
      break;
    case ACM_SUSPECT_ACK:
      RETVAL = "ACM_SUSPECT_ACK";
      break;
    case ACM_TIME_OK:
      RETVAL = "ACM_TIME_OK";
      break;
    default:
      XSRETURN_UNDEF;
    }

  OUTPUT:
    RETVAL
