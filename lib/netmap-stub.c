#include <config.h>
#include "netmap.h"

#include "smap.h"
#include "ovs-thread.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(netmap);

void
netmap_init(const struct smap *ovs_other_config)
{
    if (smap_get_bool(ovs_other_config, "netmap-init", false)) {
        static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

        if (ovsthread_once_start(&once)) {
            VLOG_ERR("NETMAP not supported in this copy of Open vSwitch.");
            ovsthread_once_done(&once);
        }
    }
}
