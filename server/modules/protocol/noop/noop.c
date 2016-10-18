/*
 *
 * Copyright (c) 2016 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl.
 *
 * Change Date: 2019-07-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */

#include <maxscale/protocol.h>
#include <maxscale/session.h>
#include <maxscale/alloc.h>
#include <maxscale/log_manager.h>
#include <maxscale/modinfo.h>
#include <maxscale/modutil.h>
#include <maxscale/protocol/mysql.h>
#include <maxscale/authenticator.h>
#include <maxscale/limits.h>
#include <netinet/tcp.h>

/**
 * Minimalistic protocol module
 *
 * This protocol module does nothing special and it transparently proxies all
 * traffic.
 */

static int noop_accept(DCB *listener);

static int noop_write(DCB *dcb, GWBUF *queue)
{
    return dcb_write(dcb, queue);
}

static int noop_read(DCB* dcb)
{
    GWBUF *read_buffer = NULL;
    int return_code = dcb_read(dcb, &read_buffer, 0);

    if (return_code <= 0)
    {
        dcb_close(dcb);
    }
    else if (dcb->dcb_role == DCB_ROLE_CLIENT_HANDLER)
    {
        return_code = MXS_SESSION_ROUTE_QUERY(dcb->session, read_buffer) ? 0 : 1;
    }
    else if (dcb->dcb_role == DCB_ROLE_BACKEND_HANDLER)
    {
        return_code = MXS_SESSION_ROUTE_REPLY(dcb->session, read_buffer) ? 0 : 1;
    }

    return return_code;
}

static int noop_drain_write(DCB *dcb)
{
    dcb_drain_writeq(dcb);
    return 1;
}

static int noop_listen(DCB *listen_dcb, char *config_bind)
{
    int rval = 0;

    if (dcb_listen(listen_dcb, config_bind, "MySQL") >= 0)
    {
        listen_dcb->func.accept = noop_accept;
        rval = 1;
    }

    return rval;
}

static int noop_error(DCB* dcb)
{
    CHK_DCB(dcb);
    MXS_SESSION *session = dcb->session;

    if (session->state != SESSION_STATE_STOPPING)
    {
        if (dcb->dcb_role == DCB_ROLE_BACKEND_HANDLER)
        {
            GWBUF *errbuf = mysql_create_custom_error(1, 0, "Lost connection to backend server.");
            void* rsession = session->router_session;
            MXS_ROUTER_OBJECT* router = session->service->router;
            MXS_ROUTER* router_instance = session->service->router_instance;
            bool succp = false;

            router->handleError(router_instance, rsession, errbuf, dcb, ERRACT_NEW_CONNECTION, &succp);
            gwbuf_free(errbuf);

            if (!succp)
            {
                spinlock_acquire(&session->ses_lock);
                session->state = SESSION_STATE_STOPPING;
                spinlock_release(&session->ses_lock);
            }
        }
        else
        {
            dcb_close(dcb);
        }
    }
    return 1;
}

static int noop_close(DCB *dcb)
{
    MXS_SESSION* session = dcb->session;

    if (session != NULL && SESSION_STATE_DUMMY != session->state)
    {
        if (dcb->dcb_role == DCB_ROLE_CLIENT_HANDLER)
        {
            CHK_SESSION(session);
            spinlock_acquire(&session->ses_lock);

            if (session->state != SESSION_STATE_STOPPING)
            {
                session->state = SESSION_STATE_STOPPING;
            }

            spinlock_release(&session->ses_lock);

            void* router_instance = session->service->router_instance;
            MXS_ROUTER_OBJECT* router = session->service->router;

            if (session->router_session)
            {
                router->closeSession(router_instance, session->router_session);
            }
        }
        else if (dcb->dcb_role == DCB_ROLE_BACKEND_HANDLER)
        {
            spinlock_acquire(&session->ses_lock);
            bool do_close = session->state == SESSION_STATE_STOPPING &&
                            session->client_dcb &&
                            session->client_dcb->state == DCB_STATE_POLLING;
            spinlock_release(&session->ses_lock);

            if (do_close)
            {
                dcb_close(session->client_dcb);
            }
        }
    }

    return 1;
}

static int noop_connect(DCB *backend_dcb, SERVER *server, MXS_SESSION *session)
{
    MySQLProtocol *proto = (MySQLProtocol*)MXS_MALLOC(sizeof(*proto));
    backend_dcb->protocol = proto;
    struct sockaddr_in serv_addr = {};
    int so = socket(AF_INET, SOCK_STREAM, 0);
    const char *host = server->name;
    unsigned short port = server->port;

    if (so < 0)
    {
        char errbuf[MXS_STRERROR_BUFLEN];
        MXS_ERROR("Establishing connection to backend server failed due to %d, %s.",
                  errno, strerror_r(errno, errbuf, sizeof(errbuf)));
        return DCBFD_CLOSED;
    }

    serv_addr.sin_family = AF_INET;
    setipaddress(&serv_addr.sin_addr, (char*)host);
    serv_addr.sin_port = htons(port);
    int sbufsize = MXS_BACKEND_SO_SNDBUF;
    int rbufsize = MXS_BACKEND_SO_RCVBUF;
    int one = 1;

    if (setsockopt(so, SOL_SOCKET, SO_SNDBUF, &sbufsize, sizeof(sbufsize)) != 0 ||
        setsockopt(so, SOL_SOCKET, SO_RCVBUF, &rbufsize, sizeof(rbufsize)) != 0 ||
        setsockopt(so, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0)
    {
        char errbuf[MXS_STRERROR_BUFLEN];
        MXS_ERROR("Failed to set socket options due to %d, %s.",
                  errno, strerror_r(errno, errbuf, sizeof(errbuf)));
        close(so);
        return DCBFD_CLOSED;
    }

    /* set socket to as non-blocking here */
    setnonblocking(so);

    if (connect(so, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0 && errno != EINPROGRESS)
    {

        char errbuf[MXS_STRERROR_BUFLEN];
        MXS_ERROR("Failed to connect backend server %s:%d due to %d, %s.",
                  host, port, errno, strerror_r(errno, errbuf, sizeof(errbuf)));

        close(so);
        return DCBFD_CLOSED;
    }

    return so;

}

/**
 * The default authenticator name for this protocol
 *
 * @return name of authenticator
 */
static char *noop_default_auth()
{
    return "NullAuthAllow";
}

static char *version_str = "1.0.0";

static int noop_change_user(DCB *backend, SERVER *server, MXS_SESSION *in_session, GWBUF *queue)
{
    gwbuf_free(queue);
    return 1;
}

/**
 * @node Accept a new connection, using the DCB code for the basic work
 *
 * For as long as dcb_accept can return new client DCBs for new connections,
 * continue to loop. The code will always give a failure return, since it
 * continues to try to create new connections until a failure occurs.
 *
 * @param listener - The Listener DCB that picks up new connection requests
 * @return 0 in success, 1 in failure
 *
 */
static int noop_accept(DCB *listener)
{
    CHK_DCB(listener);
    DCB *client_dcb;

    while ((client_dcb = dcb_accept(listener)))
    {
        client_dcb->session = session_alloc(listener->service, client_dcb);
        MySQLProtocol *proto = (MySQLProtocol*)MXS_MALLOC(sizeof(*proto));
        proto->current_command = MYSQL_COM_QUERY;
        client_dcb->protocol = proto;
        poll_add_dcb(client_dcb);
    }

    return 1;
}

/**
 * The module entry point routine. It is this routine that
 * must populate the structure that is referred to as the
 * "module object", this is a structure with the set of
 * external entry points for this module.
 *
 * @return The module object
 */
MXS_MODULE* MXS_CREATE_MODULE()
{
    static MXS_PROTOCOL MyObject =
    {
        noop_read,                  /* Read - EPOLLIN handler        */
        noop_write,                 /* Write - data from gateway     */
        noop_drain_write,           /* WriteReady - EPOLLOUT handler */
        noop_error,                 /* Error - EPOLLERR handler      */
        noop_error,                 /* HangUp - EPOLLHUP handler     */
        noop_accept,                /* Accept                        */
        noop_connect,               /* Connect                       */
        noop_close,                 /* Close                         */
        noop_listen,                /* Listen                        */
        noop_change_user,           /* Authentication                */
        NULL,                       /* Session                       */
        noop_default_auth,          /* Default authenticator         */
        NULL                        /* Send error connection limit   */
    };

    static MXS_MODULE info =
    {
        MXS_MODULE_API_PROTOCOL,
        MXS_MODULE_GA,
        MXS_PROTOCOL_VERSION,
        "No-Op protocol",
        "V1.0.0",
        &MyObject,
        NULL,
        NULL,
        NULL,
        NULL,
        {
            {MXS_END_MODULE_PARAMS}
        }
    };

    return &info;
}
