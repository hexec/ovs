#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>

#include "dirs.h"
#include "netdev-netmap.h"
#include "netmap.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "smap.h"

#include "tsc.h" /* to calibrate rdtsc */

VLOG_DEFINE_THIS_MODULE(netmap);

static void
netmap_init__(const struct smap *ovs_other_config)
{
    /* register the netmap classes */
    netdev_netmap_register();
}

void
netmap_init(const struct smap *ovs_other_config)
{
    static bool enabled = false;

    if (enabled || !ovs_other_config) {
        return;
    }

    if (smap_get_bool(ovs_other_config, "netmap-init", false)) {
        static struct ovsthread_once once_enable = OVSTHREAD_ONCE_INITIALIZER;

        if (ovsthread_once_start(&once_enable)) {
            VLOG_INFO("NETMAP Enabled - initializing...");
            calibrate_tsc();
            netmap_init__(ovs_other_config);
            enabled = true;
            VLOG_INFO("NETMAP Enabled - initialized");
            ovsthread_once_done(&once_enable);
        }
    } else {
        VLOG_INFO_ONCE("NETMAP Disabled - Use other_config:netmap-init to enable");
    }
}
