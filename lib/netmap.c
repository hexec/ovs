#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>

#include "dirs.h"
#include "netdev-netmap.h"
#include "netmap.h"
#include "netmap-utils.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "smap.h"

VLOG_DEFINE_THIS_MODULE(netmap);

void
netmap_init(const struct smap *ovs_other_config OVS_UNUSED)
{
    static bool enabled = false;

    if (enabled || !ovs_other_config) {
        return;
    }

    if (smap_get_bool(ovs_other_config, "netmap-init", false)) {
        static struct ovsthread_once once_enable = OVSTHREAD_ONCE_INITIALIZER;
        if (ovsthread_once_start(&once_enable)) {
            nm_alloc_init_global();
            netmap_calibrate_tsc();
            netdev_netmap_register();
            enabled = true;
            ovsthread_once_done(&once_enable);
            VLOG_INFO("NETMAP Enabled");
        }
    } else
        VLOG_INFO_ONCE("NETMAP Disabled - Use other_config:netmap-init to enable");
}
