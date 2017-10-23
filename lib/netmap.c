#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <net/if.h>

#include "dirs.h"
#include "fatal-signal.h"
#include "netdev-netmap.h"
#include "netmap.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "smap.h"

VLOG_DEFINE_THIS_MODULE(netmap);

//static FILE *log_stream = NULL;       /* Stream for NETMAP log redirection */

static ssize_t
netmap_log_write(void *c OVS_UNUSED, const char *buf, size_t size)
{
    char *str = xmemdup0(buf, size);

    VLOG_DBG("%s", str);
    /*
    switch (loglevel()) {
        case LOG_DEBUG:
            VLOG_DBG("%s", str);
            break;
        case LOG_INFO:
        case LOG_NOTICE:
            VLOG_INFO("%s", str);
            break;
        case LOG_WARNING:
            VLOG_WARN("%s", str);
            break;
        case LOG_ERR:
            VLOG_ERR("%s", str);
            break;
        case LOG_CRIT:
        case LOG_ALERT:
        case LOG_EMERG:
            VLOG_EMER("%s", str);
            break;
        default:
            OVS_NOT_REACHED();
    }*/

    free(str);
    return size;
}

static cookie_io_functions_t netmap_log_func = {
    .write = netmap_log_write,
};

static void
netmap_init__(const struct smap *ovs_other_config)
{
    /*
    log_stream = fopencookie(NULL, "w+", netmap_log_func);
    if (log_stream == NULL) {
        VLOG_ERR("Can't redirect NETMAP log: %s.", ovs_strerror(errno));
    } else {
        setbuf(log_stream, NULL);
    }
    */

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
            netmap_init__(ovs_other_config);
            enabled = true;
            VLOG_INFO("NETMAP Enabled - initialized");
            ovsthread_once_done(&once_enable);
        }
    } else {
        VLOG_INFO_ONCE("NETMAP Disabled - Use other_config:netmap-init to enable");
    }
}
