/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) ${year} ${author} <${email}>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBSIGROK_HARDWARE_${upper}_PROTOCOL_H
#define LIBSIGROK_HARDWARE_${upper}_PROTOCOL_H

#include <stdint.h>
#include "libsigrok.h"
#include "libsigrok-internal.h"

/* Message logging helpers with driver-specific prefix string. */
#define DRIVER_LOG_DOMAIN "${short}: "
#define SR_LOG(l, s, args...) sr_log(l, DRIVER_LOG_DOMAIN s, ## args)
#define SR_SPEW(s, args...) sr_spew(DRIVER_LOG_DOMAIN s, ## args)
#define SR_DBG(s, args...) sr_dbg(DRIVER_LOG_DOMAIN s, ## args)
#define SR_INFO(s, args...) sr_info(DRIVER_LOG_DOMAIN s, ## args)
#define SR_WARN(s, args...) sr_warn(DRIVER_LOG_DOMAIN s, ## args)
#define SR_ERR(s, args...) sr_err(DRIVER_LOG_DOMAIN s, ## args)

/** Private, per-device-instance driver context. */
struct dev_context {
	/** The current sampling limit (in number of samples). */
	uint64_t limit_samples;

	/** The current sampling limit (in ms). */
	uint64_t limit_msec;

	/** Opaque pointer passed in by the frontend. */
	void *cb_data;

	/** The current number of already received samples. */
	uint64_t num_samples;
};

SR_PRIV int ${lib}_receive_data(int fd, int revents, void *cb_data);

#endif
