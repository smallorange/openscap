/**
 * @file   rpminfo_probe.c
 * @brief  rpminfo probe
 * @author "Daniel Kopecek" <dkopecek@redhat.com>
 *
 * 2010/06/13 dkopecek@redhat.com
 *  This probe is able to process a rpminfo_object as defined in OVAL 5.4 and 5.5.
 *
 */

/*
 * Copyright 2009 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors:
 *      "Daniel Kopecek" <dkopecek@redhat.com>
 */

/*
 * rpminfo probe:
 *
 *  rpminfo_object(string name)
 *
 *  rpminfo_state(string name,
 *                string arch,
 *                string epoch,
 *                string release,
 *                string version,
 *                string evr,
 *                string signature_keyid
 *                string extended_status OVAL >= 5.10
 *              )
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <regex.h>

/* SEAP */
#include "_seap.h"
#include <probe-api.h>
#include <probe/probe.h>
#include <probe/option.h>
#include "probe/entcmp.h"
#include "common/debug_priv.h"

#include "fwupdhsi_probe.h"

int fwupdhsi_probe_offline_mode_supported()
{
	return PROBE_OFFLINE_CHROOT;
}


int fwupdhsi_probe_main(probe_ctx *ctx, void *arg)
{
	SEXP_t *val, *item, *ent, *probe_in;
	oval_schema_version_t over;
	int rpmret, i;
    uint32_t hsi = 0;
	uint32_t datatype = 0;

	// arg is NULL if regex compilation failed
	if (arg == NULL) {
		return PROBE_EINIT;
	}

	probe_in = probe_ctx_getobject(ctx);
	if (probe_in == NULL)
		return PROBE_ENOOBJ;


	over = probe_obj_get_platform_schema_version(probe_in);

        ent = probe_obj_getent (probe_in, "stream-id", 1);

        if (ent == NULL) {
                return (PROBE_ENOENT);
        }

        val = probe_ent_getval (ent);

        dD ("We are here");

	datatype = probe_ent_getdatatype(ent);
	dD("Data type %d", datatype);

	dD("Data name %s", probe_ent_getname(ent));

        hsi = SEXP_number_geti_64 (val);
        SEXP_free (val);

        dD("Get from user hsi %d", hsi);

    dD("Prepare return info");
	item = probe_item_create(OVAL_LINUX_FWUPD, NULL,
                             "hsi", OVAL_DATATYPE_INTEGER, 3,
                             NULL);

    // probe_item_setstatus (item, SYSCHAR_STATUS_ERROR);
    probe_item_collect(ctx, item);


#if 0
                {
                        SEXP_t *name;

                        for (i = 0; i < rpmret; ++i) {
				name = SEXP_string_newf("%s", reply_st[i].name);

				if (probe_entobj_cmp(ent, name) != OVAL_RESULT_TRUE) {
					SEXP_free(name);
					continue;
				}

                                item = probe_item_create(OVAL_LINUX_RPM_INFO, NULL,
                                                         "name",    OVAL_DATATYPE_SEXP, name,
                                                         "arch",    OVAL_DATATYPE_STRING, reply_st[i].arch,
                                                         "epoch",   OVAL_DATATYPE_STRING, reply_st[i].epoch,
                                                         "release", OVAL_DATATYPE_STRING, reply_st[i].release,
                                                         "version", OVAL_DATATYPE_STRING, reply_st[i].version,
                                                         "evr",     OVAL_DATATYPE_EVR_STRING, reply_st[i].evr,
                                                         "signature_keyid", OVAL_DATATYPE_STRING, reply_st[i].signature_keyid,
                                                         NULL);

				/* OVAL 5.10 added extended_name and filepaths behavior */
				if (oval_schema_version_cmp(over, OVAL_SCHEMA_VERSION(5.10)) >= 0) {
					SEXP_t *value, *bh_value;
					value = probe_entval_from_cstr(
							OVAL_DATATYPE_STRING,
							reply_st[i].extended_name,
							strlen(reply_st[i].extended_name)
					);
					probe_item_ent_add(item, "extended_name", NULL, value);
					SEXP_free(value);

					/*
					 * Parse behaviors
					 */
					value = probe_obj_getent(probe_in, "behaviors", 1);
					if (value != NULL) {
						bh_value = probe_ent_getattrval(value, "filepaths");
						if (bh_value != NULL) {
							if (SEXP_strcmp(bh_value, "true") == 0) {
								/* collect package files */
								collect_rpm_files(item, &reply_st[i], g_rpm);

							}
							SEXP_free(bh_value);
						}
						SEXP_free(value);
					}

				}


				SEXP_free(name);
                                __rpminfo_rep_free (&(reply_st[i]));

				if (probe_item_collect(ctx, item) < 0) {
					SEXP_free(ent);
					return PROBE_EUNKNOWN;
				}
                        }

                        free (reply_st);
                }
        }
#endif

	SEXP_free(ent);


        return 0;
}
