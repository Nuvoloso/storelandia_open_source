/* Copyright 2019 Tad Lebeck
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <signal.h>

#include "nuvo_pr_priv.h"
#include "nuvo.h"
#include "nuvo_pr_sync.h"
#include "nuvo_util.h"
#include "signal_handler.h"
#include "fault_inject.h"

struct nuvo_parcel_router *nuvo_pr;

// Get a connection's index in the client/server connection table.
#define GET_PR_CCONN_IDX(conn)    (conn - nuvo_pr->client_conn_table)
#define GET_PR_SCONN_IDX(conn)    (conn - nuvo_pr->server_conn_table)

void nuvo_pr_enable(bool enable_server)
{
    // enabled, once set, is never unset.
    nuvo_mutex_lock(&nuvo_pr->enable_mutex);
    if (!nuvo_pr->enabled)
    {
        nuvo_pr->enabled = 1;
        nuvo_cond_broadcast(&nuvo_pr->enable_cv);
    }
    if (enable_server && !nuvo_pr->node_init_done)
    {
        nuvo_pr->node_init_done = 1;
        nuvo_cond_broadcast(&nuvo_pr->enable_cv);
    }
    nuvo_mutex_unlock(&nuvo_pr->enable_mutex);
}

static void nuvo_pr_wait_enabled(bool is_server)
{
    nuvo_mutex_lock(&nuvo_pr->enable_mutex);
    if (is_server)
    {
        // Also wait for pr->enabled.
        while (!nuvo_pr->enabled || !nuvo_pr->node_init_done)
        {
            NUVO_LOG(pr, 50,
                     "PR Server thread waiting for notification to start");
            nuvo_cond_wait(&nuvo_pr->enable_cv, &nuvo_pr->enable_mutex);
            if (nuvo_pr->node_init_done)
            {
                NUVO_LOG(pr, 50, "PR Server thread starting");
            }
        }
        NUVO_ASSERT(nuvo_pr->node_init_done);
    }
    else
    {
        while (!nuvo_pr->enabled)
        {
            NUVO_LOG(pr, 50, "PR Thread waiting for notification to start");
            nuvo_cond_wait(&nuvo_pr->enable_cv, &nuvo_pr->enable_mutex);
            if (nuvo_pr->enabled)
            {
                NUVO_LOG(pr, 50, "PR Thread starting");
            }
        }
    }
    nuvo_mutex_unlock(&nuvo_pr->enable_mutex);
    NUVO_ASSERT(nuvo_pr->enabled);
}

static void nuvo_pr_listen_service(uint32_t events)
{
    if (events & EPOLLIN)
    {
        // accept connections
        while (1)
        {
            int sock_fd = accept(nuvo_pr->server_listen_sock, NULL, 0);
            if (sock_fd < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    // no more connections are pending
                    break;
                }
                else if (errno == EINTR)
                {
                    // we were interrupted, try again
                    continue;
                }
                else
                {
                    // TODO: implement error handling
                    NUVO_PANIC("Error during accept() call.");
                }
            }

            // make socket non blocking
            int flags = fcntl(sock_fd, F_GETFL, 0);
            if (flags == -1)
            {
                close(sock_fd);
                continue;
            }
            flags |= O_NONBLOCK;
            int ret = fcntl(sock_fd, F_SETFL, flags);
            if (ret == -1)
            {
                close(sock_fd);
                continue;
            }

            // disable Nagle algorithm
            flags = 1;
            ret = setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flags,
                             sizeof(flags));
            if (ret == -1)
            {
                close(sock_fd);
                continue;
            }

            struct nuvo_pr_server_conn *conn = nuvo_pr_sconn_alloc();
            if (conn == NULL)
            {
                close(sock_fd);
                continue;
            }

            conn->sock_fd = sock_fd;
            conn->sc_state = NUVO_SCCS_CONNECTED;
            conn->recv_state = NUVO_SCRS_HEADER;
            conn->recv_count = 0;
            conn->recv_total_bytes = 0;
            conn->send_state = NUVO_SCSS_IDLE;
            conn->send_count = 0;
            conn->send_total_bytes = 0;
            conn->recv_req = NULL;
            conn->send_req = NULL;
            conn->req_outstanding = 0;
            conn->shutdown_start_ts = 0;

            // register connection with server epoll
            union nuvo_pr_event_tag etag;
            etag.conn_index = conn - nuvo_pr->server_conn_table;
            etag.conn_gen = conn->sc_gen;
            struct epoll_event event;
            event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLHUP |
                           EPOLLERR | EPOLLET;
            event.data.u64 = etag.u64;
            ret = epoll_ctl(nuvo_pr->server_epoll_fd, EPOLL_CTL_ADD,
                            conn->sock_fd, &event);
            if (ret != 0)
            {
                close(sock_fd);
                conn->sc_state = NUVO_SCCS_CLOSED;
                nuvo_pr_sconn_free(conn);
                NUVO_ASSERT(0);
            }
            NUVO_LOG(pr, 0, "Connection Created - conn %d - Success",
                     GET_PR_SCONN_IDX(conn));
        }
    }

    if (events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP))
    {
        // error occured with the socket
        // TODO: figure out what to do here
        NUVO_PANIC("Error in listen socket events %x", events);
    }
}

static void nuvo_pr_cconn_service(struct nuvo_pr_client_conn *conn, uint32_t
                                  events, struct nuvo_dlist *completed_list)
{
    NUVO_ASSERT(conn->cc_state != NUVO_CCCS_CLOSED);

    // process any available read data first
    if (events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP))
    {
        // connection died for some reason
        NUVO_ERROR_PRINT(
            "Connection Error - conn %d terminating due to event: %x.",
            GET_PR_CCONN_IDX(conn), events);
        nuvo_pr_cconn_handle_error(conn, ENOTCONN, NUVO_CCR_EPOLL);
        return;
    }

    if (events & EPOLLIN)
    {
        if (nuvo_pr_cconn_process_recv(conn, completed_list) < 0)
        {
            return;
        }
    }

    if (events & EPOLLOUT)
    {
        if (conn->cc_state == NUVO_CCCS_CONNECTING)
        {
            // this implies the connection has been connected
            nuvo_pr_cconn_set_state(conn, NUVO_CCCS_CONNECTED);
        }

        // process any pending send operations
        if (conn->cc_state == NUVO_CCCS_CONNECTED)
        {
            nuvo_pr_cconn_process_send(conn, completed_list);
        }
    }
}

static void nuvo_pr_sconn_service(struct nuvo_pr_server_conn *conn,
                                  uint32_t                    events)
{
    NUVO_ASSERT(conn->sc_state == NUVO_SCCS_CONNECTED);

    // process any available read data first
    if (events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP))
    {
        // connection died for some reason
        NUVO_ERROR_PRINT(
            "Connection Error - conn %d terminating due to event %x.",
            GET_PR_SCONN_IDX(conn), events);
        nuvo_pr_sconn_handle_error(conn, ENOTCONN, NUVO_CCR_EPOLL);
        return;
    }

    if (events & EPOLLIN)
    {
        if (nuvo_pr_sconn_process_recv(conn) < 0)
        {
            return;
        }
    }

    if (events & EPOLLOUT)
    {
        // process any pending send operations
        if (nuvo_pr_sconn_process_send(conn) < 0)
        {
            return;
        }
    }
}

void nuvo_pr_cconn_process_epoll(sigset_t *sigset, bool is_healthy)
{
    struct epoll_event events[NUVO_PR_EPOLL_EVENTS];
    int ret;
    int wait_ms;
    int epoll_fd;

    wait_ms = (is_healthy) ? -1 : NUVO_PR_RECOVERY_EPOLL_WAIT;
    epoll_fd = (is_healthy) ? nuvo_pr->client_epoll_fd
               : nuvo_pr->cm_info.recovery_epoll_fd;

    while (nuvo_pr->shutdown_flag == 0)
    {
        ret = epoll_pwait(epoll_fd, events, NUVO_PR_EPOLL_EVENTS, wait_ms,
                          sigset);
        if (ret == 0)
        {
            // No events detected.
            if (is_healthy)
            {
                continue;
            }
            else
            {
                // Timeout hit, nothing to do now for recovering volumes.
                break;
            }
        }
        else if (ret < 0)
        {
            // We hit an error, check errno for details
            if (errno == EINTR)
            {
                if (is_healthy)
                {
                    continue;
                }
                else
                {
                    break;
                }
            }
            // TODO: We already panic in the client thread, we should
            // handle this more gracefully.
            NUVO_PANIC_ERRNO(errno, "Error during epoll_wait()");
        }

        // We received some events, process them
        struct nuvo_pr_client_conn *conn;
        union nuvo_pr_event_tag     etag;
        for (struct epoll_event *cur = &events[0], *end = &events[ret];
             cur < end; cur++)
        {
            etag.u64 = cur->data.u64;
            struct nuvo_dlist completed_list;
            nuvo_dlist_init(&completed_list);
            NUVO_ASSERT(etag.conn_index <
                        NUVO_ARRAY_LENGTH(nuvo_pr->client_conn_table));
            conn = &nuvo_pr->client_conn_table[etag.conn_index];
            nuvo_mutex_lock(&conn->cc_mutex);
            if (conn->cc_gen == etag.conn_gen)
            {
                if (is_healthy)
                {
                    if ((conn->cc_state == NUVO_CCCS_CONNECTED) ||
                        (conn->cc_state == NUVO_CCCS_CONNECTING))
                    {
                        nuvo_pr_cconn_service(conn, cur->events,
                                              &completed_list);
                    }
                }
                else
                {
                    if (NUVO_PR_IS_CCONN_IN_RECOVERY(cconn))
                    {
                        nuvo_pr_cconn_recovery_epoll_event(conn, cur->events,
                                                           &completed_list);
                    }
                }
            }
            else
            {
                NUVO_ERROR_PRINT("Epoll event for stale connection dropped.");
            }
            nuvo_mutex_unlock(&conn->cc_mutex);

            struct nuvo_io_request *req;
            while ((req = nuvo_dlist_remove_head_object(&completed_list,
                                                        struct nuvo_io_request,
                                                        list_node)) != NULL)
            {
                nuvo_pr_complete(req);
            }
        }
    }
}

void nuvo_pr_cconn_recovery_epoll_event(struct nuvo_pr_client_conn *conn,
                                        uint32_t                    events,
                                        struct nuvo_dlist          *completed_list)
{
    NUVO_ASSERT(NUVO_PR_IS_CCONN_IN_RECOVERY(cconn));

    // process any available read data first
    if (events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP))
    {
        // connection died for some reason
        NUVO_ERROR_PRINT(
            "Connection Error - conn %d terminating due to event: %x.",
            GET_PR_CCONN_IDX(conn), events);
        nuvo_pr_cconn_handle_error(conn, NUVO_CCR_EPOLL, ENOTCONN);

        return;
    }

    if (events & EPOLLIN)
    {
        if (nuvo_pr_cconn_process_recv(conn, completed_list) < 0)
        {
            return;
        }
    }

    if (events & EPOLLOUT)
    {
        if (conn->cc_state == NUVO_CCCS_RECONNECT)
        {
            // The socket is up and ready to start sending
            nuvo_pr_cconn_set_state(conn, NUVO_CCCS_RESEND_READY);
            conn->cc_resend_phase = NUVO_RESEND_CONFIG;
            conn->backoff_cnt = 0;
        }
    }
}

/*
 * \brief This thread handles the socket error recovery for client and server
 *
 * This thread is woken up when an error is encountered during a socket send
 * or receive.  This thread will iterate through the active client and server
 * connections looking for a connection in the error state.  It will then
 * attempt to fix the connection (teardown and reconnect the socket).
 * Client side recovery - Store in flight ops in a retry queue and teardown
 * the existing socket.  Bring the socket back up and resend the in flight ops
 * Server side - Throw away all in flight ops.  Teardown the existing socket
 * and wait for client to reconnect.
 */
static void *nuvo_pr_conn_mgr_thread(void *arg)
{
    (void)arg;

    nuvo_pr_wait_enabled(false);

    while (1)
    {
        // Wait for notification of socket failure
        nuvo_mutex_lock(&nuvo_pr->cm_info.cm_work_mutex);
        while (nuvo_pr->cm_info.conn_recovery_cnt == 0)
        {
            nuvo_cond_wait(&nuvo_pr->cm_info.cm_work_cv,
                           &nuvo_pr->cm_info.cm_work_mutex);
        }
        nuvo_mutex_unlock(&nuvo_pr->cm_info.cm_work_mutex);

        // To ensure shutdown happens, we bump conn_recovery_cnt after
        // the shutdown_flag is set.
        if (nuvo_pr->shutdown_flag != 0)
        {
            break;
        }

        NUVO_LOG(pr, 50, "Connection Manager - Thread wake up.");

        // Find client connection that needs error recovery
        struct nuvo_pr_client_conn *cconn = nuvo_pr_get_recovery_cconn();
        while (cconn != NULL)
        {
            nuvo_mutex_lock(&cconn->cc_mutex);
            if (cconn->cc_state == NUVO_CCCS_ERROR)
            {
                // Start recovery for the client connection
                // Once socket is up, conn_mgr thread will be notified
                nuvo_pr_cconn_recovery_start(cconn);
            }

            if (cconn->cc_state == NUVO_CCCS_RESEND_READY)
            {
                // Finish recovery.  It is unlikely, but possible that the
                // above cconn_recovery_start call moved us directly into
                // the RESEND_READY state.
                nuvo_pr_cconn_recovery_resend(cconn);
            }
            nuvo_mutex_unlock(&cconn->cc_mutex);

            cconn = nuvo_pr_get_recovery_cconn();
        }

        // Find server connection that needs error recovery
        struct nuvo_pr_server_conn *sconn = nuvo_pr_get_recovery_sconn();
        while (sconn != NULL)
        {
            nuvo_mutex_lock(&sconn->sc_mutex);

            // Do the recovery for the server connection (shutdown connection)
            nuvo_pr_sconn_recovery_start(sconn);

            nuvo_mutex_unlock(&sconn->sc_mutex);

            sconn = nuvo_pr_get_recovery_sconn();
        }

        // Check epoll for any events on the recovering connections
        nuvo_pr_cconn_process_epoll(NULL, false);

        NUVO_LOG(pr, 50, "Connection Manager - Thread work done.");
    }

    pthread_exit(0);

    return (NULL);
}

static void *nuvo_pr_client_thread(void *arg)
{
    (void)arg;

    int ret;
    // block the signal SIGUSR1 while we work, so that we can catch it on the
    // next call to epoll_pwait()
    sigset_t sigset, orig_sigset;
    // get the current mask
    ret = pthread_sigmask(SIG_SETMASK, NULL, &sigset);
    if (ret != 0)
    {
        NUVO_PANIC("Failed to get signal mask.");
        return (NULL);
    }
    // block SIGUSR1
    sigaddset(&sigset, SIGUSR1);
    ret = pthread_sigmask(SIG_SETMASK, &sigset, &orig_sigset);
    if (ret != 0)
    {
        NUVO_PANIC("Failed to set signal mask.");
        return (NULL);
    }
    // orig_sigset has original, unblocked mask

    nuvo_pr_wait_enabled(false);

    nuvo_pr_cconn_process_epoll(&orig_sigset, true);

    return (NULL);
}

static void *nuvo_pr_server_thread(void *arg)
{
    (void)arg;

    int ret;
    // block the signal SIGUSR1 while we work, so that we can catch it on the
    // next call to epoll_pwait()
    sigset_t sigset, orig_sigset;
    // get the current mask
    ret = pthread_sigmask(SIG_SETMASK, NULL, &sigset);
    if (ret != 0)
    {
        NUVO_PANIC("Failed to get signal mask.");
        return (NULL);
    }
    // block SIGUSR1
    sigaddset(&sigset, SIGUSR1);
    ret = pthread_sigmask(SIG_SETMASK, &sigset, &orig_sigset);
    if (ret != 0)
    {
        NUVO_PANIC("Failed to set signal mask.");
        return (NULL);
    }
    // orig_sigset has original, unblocked mask

    nuvo_pr_wait_enabled(true);

    // poll the epoll, and fire off events as needed
    struct epoll_event events[NUVO_PR_EPOLL_EVENTS];

    while (nuvo_pr->shutdown_flag == 0)
    {
        ret = epoll_pwait(nuvo_pr->server_epoll_fd, events,
                          NUVO_PR_EPOLL_EVENTS, -1, &orig_sigset);
        if (ret == -1)
        {
            if (errno == EINTR)
            {
                if (nuvo_pr->shutdown_flag != 0)
                {
                    break;
                }
                else
                {
                    continue;
                }
            }
            // TODO: panic? this should not happen
            NUVO_PANIC_ERRNO(errno, "Error during epoll_wait()");
            break;
        }

        struct nuvo_pr_server_conn *conn;
        union nuvo_pr_event_tag     etag;
        for (struct epoll_event *cur = &events[0], *end = &events[ret];
             cur < end; cur++)
        {
            etag.u64 = cur->data.u64;
            // first check for server listen socket
            if (etag.conn_index == NUVO_PR_INVALID32)
            {
                nuvo_pr_listen_service(cur->events);
            }
            else
            {
                NUVO_ASSERT(etag.conn_index < NUVO_ARRAY_LENGTH(
                                nuvo_pr->client_conn_table));
                conn = &nuvo_pr->server_conn_table[etag.conn_index];
                nuvo_mutex_lock(&conn->sc_mutex);
                if (conn->sc_gen == etag.conn_gen)
                {
                    // If we are not connected we are closed or tearing down,
                    // so don't do any additional processing on this connection.
                    if (conn->sc_state == NUVO_SCCS_CONNECTED)
                    {
                        nuvo_pr_sconn_service(conn, cur->events);
                    }
                }
                else
                {
                    NUVO_ERROR_PRINT(
                        "Epoll event for stale connection dropped.");
                }
                nuvo_mutex_unlock(&conn->sc_mutex);
            }
        }
    }

    return (NULL);
}

nuvo_return_t nuvo_pr_init(uint_fast16_t server_port)
{
    int ret;

    // register signal handler
    ret = nuvo_register_signal_handlers();
    if (ret == -1)
    {
        ret = -NUVO_E_SIG_HANDLER;
        goto exit_sig;
    }

    size_t pr_size = sizeof(struct nuvo_parcel_router);
    nuvo_pr = aligned_alloc(NUVO_BLOCK_SIZE, pr_size + ((NUVO_BLOCK_SIZE -
                                                         1ull) & (-pr_size)));

    if (nuvo_pr == NULL)
    {
        ret = -NUVO_ENOMEM;
        goto exit_nuvo_alloc;
    }

    memset(nuvo_pr, 0, sizeof(*nuvo_pr));

    ret = nuvo_pr_req_pool_init(&nuvo_pr->client_req_pool);
    if (ret < 0)
    {
        ret = -NUVO_ENOMEM;
        goto exit_client_req;
    }

    ret = nuvo_pr_req_pool_init(&nuvo_pr->server_req_pool);
    if (ret < 0)
    {
        ret = -NUVO_ENOMEM;
        goto exit_server_req;
    }

    ret = nuvo_pr_buf_pool_init(&nuvo_pr->client_buf_pool);
    if (ret < 0)
    {
        ret = -NUVO_ENOMEM;
        goto exit_client_buf;
    }

    ret = nuvo_pr_buf_pool_init(&nuvo_pr->server_buf_pool);
    if (ret < 0)
    {
        ret = -NUVO_ENOMEM;
        goto exit_server_buf;
    }


    nuvo_pr->node_used = 0;
    nuvo_pr->device_count = 0;
    nuvo_pr->client_conn_used = 0;
    nuvo_pr->server_conn_used = 0;
    nuvo_pr->pdef_used = 0;


    nuvo_list_init(&nuvo_pr->node_free_list);
    nuvo_dlist_init(&nuvo_pr->client_conn_free_list);
    nuvo_dlist_init(&nuvo_pr->client_conn_active_list);
    nuvo_dlist_init(&nuvo_pr->client_conn_error_list);
    nuvo_dlist_init(&nuvo_pr->server_conn_free_list);
    nuvo_dlist_init(&nuvo_pr->server_conn_active_list);
    nuvo_pr->pdef_free_list = NUVO_PR_INVALID32;

    nuvo_pr->client_epoll_fd = -1;
    nuvo_pr->server_epoll_fd = -1;
    nuvo_pr->cm_info.recovery_epoll_fd = -1;

    uuid_clear(nuvo_pr->local_node_id);
    nuvo_pr->shutdown_flag = 0;
    nuvo_pr->enabled = 0;

    // This will change to 0 once the kontroller notification piece is in.
    nuvo_pr->node_init_done = 1;

    nuvo_pr->pr_test_info = NULL;

    // init mutexes

    ret = nuvo_mutex_init(&nuvo_pr->enable_mutex);
    if (ret != 0)
    {
        ret = -NUVO_ENOMEM;
        goto exit_mutex_enable;
    }

    ret = nuvo_cond_init(&nuvo_pr->enable_cv);
    if (ret != 0)
    {
        ret = -NUVO_ENOMEM;
        goto exit_cv_enable;
    }

    ret = nuvo_mutex_init(&nuvo_pr->node_mutex);
    if (ret != 0)
    {
        ret = -NUVO_ENOMEM;
        goto exit_mutex_node;
    }
    ret = nuvo_mutex_init(&nuvo_pr->device_mutex);
    if (ret != 0)
    {
        ret = -NUVO_ENOMEM;
        goto exit_mutex_device;
    }
    ret = nuvo_mutex_init(&nuvo_pr->client_conn_mutex);
    if (ret != 0)
    {
        ret = -NUVO_ENOMEM;
        goto exit_mutex_client;
    }
    ret = nuvo_mutex_init(&nuvo_pr->server_conn_mutex);
    if (ret != 0)
    {
        ret = -NUVO_ENOMEM;
        goto exit_mutex_server;
    }
    ret = nuvo_mutex_init(&nuvo_pr->pdef_mutex);
    if (ret != 0)
    {
        ret = -NUVO_ENOMEM;
        goto exit_mutex_pdef;
    }

    ret = nuvo_pr_conn_mgr_init();
    if (ret != 0)
    {
        ret = -NUVO_ENOMEM;
        goto exit_conn_mgr_init;
    }

    // setup epolls
    nuvo_pr->client_epoll_fd = epoll_create1(0);
    if (nuvo_pr->client_epoll_fd == -1)
    {
        // TODO: error codes and such
        ret = -NUVO_ENOMEM;
        goto exit_client_epoll;
    }

    nuvo_pr->server_epoll_fd = epoll_create1(0);
    if (nuvo_pr->server_epoll_fd == -1)
    {
        // TODO: error codes and such
        ret = -NUVO_ENOMEM;
        goto exit_server_epoll;
    }

    // init pthread
    ret = pthread_create(&nuvo_pr->client_thread, NULL, nuvo_pr_client_thread,
                         NULL);
    if (ret < 0)
    {
        // TODO: error codes and such
        ret = -NUVO_ENOMEM;
        goto exit_client_thread;
    }

    ret = pthread_create(&nuvo_pr->server_thread, NULL, nuvo_pr_server_thread,
                         NULL);
    if (ret < 0)
    {
        // TODO: error codes and such
        ret = -NUVO_ENOMEM;
        goto exit_server_thread;
    }

    // start server listener
    ret = nuvo_pr_server_sock_init(server_port);
    if (ret != 0)
    {
        goto exit_sock_init;
    }

    // socket setup correctly, put on server epoll
    union nuvo_pr_event_tag etag;
    etag.conn_index = NUVO_PR_INVALID32;
    etag.conn_gen = 0;
    struct epoll_event event;
    event.events = EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR | EPOLLET;
    event.data.u64 = etag.u64;
    ret = epoll_ctl(nuvo_pr->server_epoll_fd, EPOLL_CTL_ADD,
                    nuvo_pr->server_listen_sock, &event);
    if (ret != 0)
    {
        // TODO: error codes and such
        ret = -NUVO_E_EPOLL_CTL;
        goto exit_epoll_add;
    }

    // setup local node
    nuvo_mutex_lock(&nuvo_pr->node_mutex);
    struct nuvo_pr_node_desc *node = nuvo_pr_node_alloc();
    nuvo_mutex_unlock(&nuvo_pr->node_mutex);
    NUVO_ASSERT(node != NULL);
    if (&nuvo_pr->node_table[NUVO_PR_LOCAL_NODE_INDEX] != node)
    {
        NUVO_PANIC("Failed to setup local node at NUVO_PR_LOCAL_NODE_INDEX,");
    }
    node->port = 0;
    strncpy(node->address, "0.0.0.0", 64);

    // everything is ready to go
    return (0);

exit_epoll_add:
    close(nuvo_pr->server_listen_sock);
exit_sock_init:
    nuvo_pr->shutdown_flag = 1;
    nuvo_pr_enable(true);
    pthread_kill(nuvo_pr->server_thread, SIGUSR1);
    pthread_join(nuvo_pr->server_thread, NULL);
exit_server_thread:
    nuvo_pr->shutdown_flag = 1;
    nuvo_pr_enable(true);
    pthread_kill(nuvo_pr->client_thread, SIGUSR1);
    pthread_join(nuvo_pr->client_thread, NULL);
exit_client_thread:
    close(nuvo_pr->server_epoll_fd);
exit_server_epoll:
    close(nuvo_pr->client_epoll_fd);
exit_client_epoll:
    nuvo_pr_conn_mgr_destroy();
exit_conn_mgr_init:
    nuvo_mutex_destroy(&nuvo_pr->pdef_mutex);
exit_mutex_pdef:
    nuvo_mutex_destroy(&nuvo_pr->server_conn_mutex);
exit_mutex_server:
    nuvo_mutex_destroy(&nuvo_pr->client_conn_mutex);
exit_mutex_client:
    nuvo_mutex_destroy(&nuvo_pr->device_mutex);
exit_mutex_device:
    nuvo_mutex_destroy(&nuvo_pr->node_mutex);
exit_mutex_node:
    nuvo_cond_destroy(&nuvo_pr->enable_cv);
exit_cv_enable:
    nuvo_mutex_destroy(&nuvo_pr->enable_mutex);
exit_mutex_enable:
    nuvo_pr_buf_pool_destroy(&nuvo_pr->server_buf_pool);
exit_server_buf:
    nuvo_pr_buf_pool_destroy(&nuvo_pr->client_buf_pool);
exit_client_buf:
    nuvo_pr_req_pool_destroy(&nuvo_pr->server_req_pool);
exit_server_req:
    nuvo_pr_req_pool_destroy(&nuvo_pr->client_req_pool);
exit_client_req:
    free(nuvo_pr);
exit_nuvo_alloc:
exit_sig:
    return (ret);
}

nuvo_return_t nuvo_pr_get_node_uuid(uuid_t local_node_id)
{
    nuvo_return_t ret = 0;

    nuvo_mutex_lock(&nuvo_pr->node_mutex);
    if (!uuid_is_null(nuvo_pr->local_node_id))
    {
        uuid_copy(local_node_id, nuvo_pr->local_node_id);
    }
    else
    {
        ret = -NUVO_ENOENT;
    }
    nuvo_mutex_unlock(&nuvo_pr->node_mutex);
    return (ret);
}

nuvo_return_t nuvo_pr_set_node_uuid(const uuid_t local_node_id)
{
    nuvo_return_t ret = 0;

    nuvo_mutex_lock(&nuvo_pr->node_mutex);

    if (uuid_is_null(nuvo_pr->local_node_id))
    {
        struct nuvo_pr_node_desc *node;

        uuid_copy(nuvo_pr->local_node_id, local_node_id);

        node = &nuvo_pr->node_table[NUVO_PR_LOCAL_NODE_INDEX];
        uuid_copy(node->id, local_node_id);
    }
    else
    {
        if (uuid_compare(nuvo_pr->local_node_id, local_node_id) != 0)
        {
            ret = -NUVO_EEXIST;
        }
    }

    nuvo_mutex_unlock(&nuvo_pr->node_mutex);
    return (ret);
}

void nuvo_pr_shutdown()
{
    // NOTE: This function assumes upper layers have been shutdown and freed their resources
    struct epoll_event      event;
    struct nuvo_io_request *req;
    struct nuvo_dlist       complete_list;

    nuvo_dlist_init(&complete_list);

    // unregister listening socket and close it
    epoll_ctl(nuvo_pr->server_epoll_fd, EPOLL_CTL_DEL,
              nuvo_pr->server_listen_sock, &event);
    close(nuvo_pr->server_listen_sock);

    // close down all client connections (on both the active and error list)
    struct nuvo_pr_client_conn *cconn;
    while ((cconn = nuvo_dlist_get_head_object(
                &nuvo_pr->client_conn_active_list,
                struct nuvo_pr_client_conn, list_node)) != NULL)
    {
        nuvo_mutex_lock(&cconn->cc_mutex);
        nuvo_pr_cconn_shutdown(cconn, &complete_list, 0, NUVO_CCR_NORMAL);
        nuvo_mutex_unlock(&cconn->cc_mutex);

        while ((req = nuvo_dlist_remove_head_object(&complete_list,
                                                    struct nuvo_io_request,
                                                    list_node)) != NULL)
        {
            req->callback(req);
        }
    }

    while ((cconn = nuvo_dlist_get_head_object(&nuvo_pr->client_conn_error_list,
                                               struct nuvo_pr_client_conn,
                                               list_node)) != NULL)
    {
        nuvo_mutex_lock(&cconn->cc_mutex);
        nuvo_pr_cconn_shutdown(cconn, &complete_list, 0, NUVO_CCR_NORMAL);
        nuvo_mutex_unlock(&cconn->cc_mutex);

        while ((req = nuvo_dlist_remove_head_object(&complete_list,
                                                    struct nuvo_io_request,
                                                    list_node)) != NULL)
        {
            req->callback(req);
        }
    }

    // close down all server connections
    struct nuvo_pr_server_conn *sconn;
    while ((sconn = nuvo_dlist_get_head_object(
                &nuvo_pr->server_conn_active_list, struct nuvo_pr_server_conn,
                list_node)) != NULL)
    {
        nuvo_mutex_lock(&sconn->sc_mutex);
        nuvo_pr_sconn_shutdown(sconn, 0, NUVO_CCR_NORMAL);
        nuvo_mutex_unlock(&sconn->sc_mutex);
    }

    // signal shutdown to threads
    nuvo_pr->shutdown_flag = 1;

    nuvo_pr_enable(true);  // enable the threads to see shutdown

    // shutdown connection manager thread
    nuvo_pr_conn_mgr_destroy();

    pthread_kill(nuvo_pr->server_thread, SIGUSR1);
    pthread_kill(nuvo_pr->client_thread, SIGUSR1);

    // wait for threads to finish
    pthread_join(nuvo_pr->server_thread, NULL);
    pthread_join(nuvo_pr->client_thread, NULL);

    // now close down epolls
    close(nuvo_pr->client_epoll_fd);
    close(nuvo_pr->server_epoll_fd);

    // TODO: There may still be outstanding IO requests, should we wait for them?

    // destroy mutexes
    nuvo_mutex_destroy(&nuvo_pr->pdef_mutex);
    nuvo_mutex_destroy(&nuvo_pr->server_conn_mutex);
    nuvo_mutex_destroy(&nuvo_pr->client_conn_mutex);
    nuvo_mutex_destroy(&nuvo_pr->device_mutex);
    nuvo_mutex_destroy(&nuvo_pr->node_mutex);

    nuvo_pr_buf_pool_destroy(&nuvo_pr->server_buf_pool);
    nuvo_pr_buf_pool_destroy(&nuvo_pr->client_buf_pool);

    nuvo_pr_req_pool_destroy(&nuvo_pr->server_req_pool);
    nuvo_pr_req_pool_destroy(&nuvo_pr->client_req_pool);

    if (nuvo_pr->pr_test_info != NULL)
    {
        free(nuvo_pr->pr_test_info);
    }

    // finally, free the nuvo_pr struct
    free(nuvo_pr);
}

struct nuvo_pr_node_desc *nuvo_pr_node_alloc()
{
    NUVO_ASSERT_MUTEX_HELD(&nuvo_pr->node_mutex);
    // this routine requires the caller to hold nuvo_pr->node_mutex locked
    struct nuvo_pr_node_desc *node_desc = nuvo_list_remove_head_object(
        &nuvo_pr->node_free_list, struct nuvo_pr_node_desc, list_next);

    if (node_desc == NULL)
    {
        if (nuvo_pr->node_used < NUVO_PR_MAX_NODES)
        {
            node_desc = &nuvo_pr->node_table[nuvo_pr->node_used++];
            nuvo_lnode_init(&node_desc->list_next);
        }
    }

    if (node_desc != NULL)
    {
        node_desc->conn = NULL;
        nuvo_mutex_init(&node_desc->nd_mutex);
    }

    return (node_desc);
}

void nuvo_pr_node_free(struct nuvo_pr_node_desc *node_desc)
{
    NUVO_ASSERT(node_desc - nuvo_pr->node_table >= 0);
    NUVO_ASSERT(node_desc - nuvo_pr->node_table < (intptr_t)NUVO_ARRAY_LENGTH(
                    nuvo_pr->node_table));

    NUVO_ASSERT(node_desc->conn == NULL);
    node_desc->address[0] = '\0';
    nuvo_mutex_destroy(&node_desc->nd_mutex);
    nuvo_mutex_lock(&nuvo_pr->node_mutex);
    nuvo_list_insert_head(&nuvo_pr->node_free_list, &node_desc->list_next);
    nuvo_mutex_unlock(&nuvo_pr->node_mutex);
}

nuvo_return_t nuvo_pr_node_find(const uuid_t node_id, uint_fast16_t *index)
{
    NUVO_ASSERT_MUTEX_HELD(&nuvo_pr->node_mutex);
    // scan through all the used node entries
    struct nuvo_pr_node_desc *cur = nuvo_pr->node_table;
    struct nuvo_pr_node_desc *end = nuvo_pr->node_table + nuvo_pr->node_used;
    for (; cur < end; ++cur)
    {
        if (cur->address[0] != '\0' && uuid_compare(cur->id, node_id) == 0)
        {
            *index = cur - nuvo_pr->node_table;
            return (0);
        }
    }

    return (-NUVO_ENOENT);
}

struct nuvo_pr_node_desc *nuvo_pr_node_get_locked(const uuid_t node_id)
{
    struct nuvo_pr_node_desc *node_desc = NULL;
    uint_fast16_t             index;
    nuvo_return_t             ret;

    nuvo_mutex_lock(&nuvo_pr->node_mutex);

    ret = nuvo_pr_node_find(node_id, &index);

    if (ret != -NUVO_ENOENT)
    {
        node_desc = &nuvo_pr->node_table[index];
        nuvo_mutex_lock(&node_desc->nd_mutex);
    }

    nuvo_mutex_unlock(&nuvo_pr->node_mutex);

    return (node_desc);
}

nuvo_return_t nuvo_pr_node_insert(const uuid_t node_id, const char address[],
                                  uint_fast16_t port)
{
    size_t len = strlen(address);

    if (len > NUVO_MAX_ADDR_LEN)
    {
        return (-NUVO_EINVAL);
    }

    nuvo_mutex_lock(&nuvo_pr->node_mutex);
    // do a find first just to make sure node doesn't exist already
    uint_fast16_t index = 0;
    nuvo_return_t ret = nuvo_pr_node_find(node_id, &index);

    if (ret != -NUVO_ENOENT)
    {
        // node already exists
        nuvo_mutex_unlock(&nuvo_pr->node_mutex);
        return (-NUVO_EEXIST);
    }

    struct nuvo_pr_node_desc *node_desc = nuvo_pr_node_alloc();

    if (node_desc == NULL)
    {
        nuvo_mutex_unlock(&nuvo_pr->node_mutex);
        return (-NUVO_ENOMEM);
    }

    uuid_copy(node_desc->id, node_id);
    strncpy(node_desc->address, address, NUVO_ARRAY_LENGTH(node_desc->address));
    node_desc->address[NUVO_ARRAY_LENGTH(node_desc->address) - 1] = '\0';
    node_desc->port = port;
    node_desc->conn = NULL;

    nuvo_mutex_unlock(&nuvo_pr->node_mutex);

    return (0);
}

nuvo_return_t nuvo_pr_node_remove(const uuid_t node_id)
{
    struct nuvo_dlist completed_list;

    nuvo_dlist_init(&completed_list);
    nuvo_mutex_lock(&nuvo_pr->node_mutex);
    // do a find first just to make sure node doesn't exist already
    uint_fast16_t index = 0;
    nuvo_return_t ret = nuvo_pr_node_find(node_id, &index);

    if (ret == -NUVO_ENOENT)
    {
        // no such node found
        nuvo_mutex_unlock(&nuvo_pr->node_mutex);
        return (-NUVO_ENOENT);
    }

    // we're not allowed to remove the local node
    if (index == NUVO_PR_LOCAL_NODE_INDEX)
    {
        // tisk tisk
        nuvo_mutex_unlock(&nuvo_pr->node_mutex);
        return (-NUVO_EINVAL);
    }

    // remove all devices on this node
    nuvo_pr_device_remove_all_index(index);

    struct nuvo_pr_node_desc *node_desc = &nuvo_pr->node_table[index];
    nuvo_mutex_lock(&node_desc->nd_mutex);

    // remove existing pdefs
    nuvo_pr_pdef_remove_all(node_desc);

    node_desc->address[0] = '\0';   // invalidates the node for finding
    nuvo_mutex_unlock(&nuvo_pr->node_mutex);

    struct nuvo_pr_client_conn *conn = node_desc->conn;
    if (conn != NULL)
    {
        nuvo_mutex_lock(&conn->cc_mutex);
        nuvo_pr_cconn_shutdown(conn, &completed_list, 0, NUVO_CCR_NODE_REMOVE);

        NUVO_ASSERT(conn->cc_state == NUVO_CCCS_CLOSED);

        nuvo_pr_cconn_free(conn);
        nuvo_mutex_unlock(&conn->cc_mutex);
        node_desc->conn = NULL;
    }
    nuvo_mutex_unlock(&node_desc->nd_mutex);

    nuvo_pr_node_free(node_desc);

    struct nuvo_io_request *req;
    while ((req = nuvo_dlist_remove_head_object(&completed_list,
                                                struct nuvo_io_request,
                                                list_node)) != NULL)
    {
        nuvo_pr_complete(req);
    }

    return (0);
}

nuvo_return_t nuvo_pr_node_init_done(const uuid_t node_id, bool clear)
{
    nuvo_return_t ret;
    uint_fast16_t index = 0;

    // Clearing is for testing purposes only, and applies only to the local
    // node. Let it go through, even before node_id has been set.
    if (uuid_is_null(node_id) || clear ||
        (uuid_compare(node_id, nuvo_pr->local_node_id) == 0))
    {
        nuvo_pr_kontroller_config_done(clear);
        return (0);
    }

    // The kontroller notifications are under development.  Once complete this
    // remote node config complete notification may no longer be needed.
    nuvo_mutex_lock(&nuvo_pr->node_mutex);
    ret = nuvo_pr_node_find(node_id, &index);
    nuvo_mutex_unlock(&nuvo_pr->node_mutex);

    if (ret <= 0)
    {
        return (ret);
    }

    // TODO: Trigger remote node device recovery from here (for testing).
    return (0);
}

nuvo_return_t nuvo_pr_device_find(const uuid_t dev_id, uint_fast32_t *index)
{
    uint_fast32_t start = 0, end = nuvo_pr->device_count;

    while (1)
    {
        if (start == end)
        {
            *index = start;
            return (-NUVO_ENODEV);
        }
        else
        {
            uint_fast32_t mid = (start + end) / 2;
            int           cmp = uuid_compare(dev_id,
                                             nuvo_pr->device_list[mid].id);
            if (cmp < 0)
            {
                end = mid;
            }
            else if (cmp > 0)
            {
                start = mid + 1;
            }
            else
            {
                *index = mid;
                return (0);
            }
        }
    }

    return (-NUVO_ENODEV);
}

nuvo_return_t nuvo_pr_device_lookup(const uuid_t dev_id, uuid_t *node_id)
{
    nuvo_return_t ret;
    uint_fast32_t index;

    nuvo_mutex_lock(&nuvo_pr->device_mutex);

    ret = nuvo_pr_device_find(dev_id, &index);
    if (ret < 0)
    {
        nuvo_mutex_unlock(&nuvo_pr->device_mutex);
        return (-NUVO_ENODEV);
    }

    if (node_id != NULL)
    {
        uuid_copy(*node_id,
                  nuvo_pr->node_table[nuvo_pr->device_list[index].node_index].id);
    }

    nuvo_mutex_unlock(&nuvo_pr->device_mutex);
    return (0);
}

bool nuvo_pr_is_device_remote(const uuid_t dev_id)
{
    nuvo_return_t ret;
    uint_fast32_t index;

    nuvo_mutex_lock(&nuvo_pr->device_mutex);

    ret = nuvo_pr_device_find(dev_id, &index);
    if (ret < 0)
    {
        nuvo_mutex_unlock(&nuvo_pr->device_mutex);
        return (false);
    }

    if (nuvo_pr->device_list[index].node_index != NUVO_PR_LOCAL_NODE_INDEX)
    {
        nuvo_mutex_unlock(&nuvo_pr->device_mutex);
        return (true);
    }

    nuvo_mutex_unlock(&nuvo_pr->device_mutex);
    return (false);
}

nuvo_return_t nuvo_pr_device_update(const uuid_t dev_id, const uuid_t node_id)
{
    nuvo_return_t ret;
    uint_fast16_t node_index;

    // first find the node
    nuvo_mutex_lock(&nuvo_pr->node_mutex);

    ret = nuvo_pr_node_find(node_id, &node_index);
    if (ret < 0)
    {
        nuvo_mutex_unlock(&nuvo_pr->node_mutex);
        return (-NUVO_ENOENT);
    }

    uint_fast32_t index = 0;
    nuvo_mutex_lock(&nuvo_pr->device_mutex);
    ret = nuvo_pr_device_find(dev_id, &index);

    if (ret < 0)
    {
        nuvo_mutex_unlock(&nuvo_pr->node_mutex);
        nuvo_mutex_unlock(&nuvo_pr->device_mutex);
        return (-NUVO_ENODEV);
    }

    nuvo_pr->device_list[index].node_index = node_index;

    nuvo_mutex_unlock(&nuvo_pr->node_mutex);
    nuvo_mutex_unlock(&nuvo_pr->device_mutex);
    return (0);
}

nuvo_return_t nuvo_pr_device_insert(const uuid_t dev_id, const uuid_t node_id)
{
    uint_fast16_t node_index = 0;
    uint_fast32_t insert_index = 0;
    nuvo_return_t ret;

    // first find the node
    nuvo_mutex_lock(&nuvo_pr->node_mutex);

    ret = nuvo_pr_node_find(node_id, &node_index);
    if (ret < 0)
    {
        nuvo_mutex_unlock(&nuvo_pr->node_mutex);
        return (-NUVO_ENOENT);
    }

    nuvo_mutex_lock(&nuvo_pr->device_mutex);

    ret = nuvo_pr_device_find(dev_id, &insert_index);

    if (ret >= 0)
    {
        nuvo_mutex_unlock(&nuvo_pr->node_mutex);
        nuvo_mutex_unlock(&nuvo_pr->device_mutex);
        return (-NUVO_EEXIST);
    }

    if (nuvo_pr->device_count == NUVO_PR_MAX_DEVS)
    {
        nuvo_mutex_unlock(&nuvo_pr->node_mutex);
        nuvo_mutex_unlock(&nuvo_pr->device_mutex);
        return (-NUVO_ENOMEM);
    }

    for (uint_fast32_t i = nuvo_pr->device_count; i > insert_index; i--)
    {
        nuvo_pr->device_list[i] = nuvo_pr->device_list[i - 1];
    }
    nuvo_pr->device_count++;

    uuid_copy(nuvo_pr->device_list[insert_index].id, dev_id);
    nuvo_pr->device_list[insert_index].node_index = node_index;

    nuvo_mutex_unlock(&nuvo_pr->node_mutex);
    nuvo_mutex_unlock(&nuvo_pr->device_mutex);
    return (0);
}

nuvo_return_t nuvo_pr_device_remove(const uuid_t dev_id)
{
    uint_fast32_t index = 0;

    nuvo_mutex_lock(&nuvo_pr->device_mutex);
    nuvo_return_t ret = nuvo_pr_device_find(dev_id, &index);

    if (ret < 0)
    {
        nuvo_mutex_unlock(&nuvo_pr->device_mutex);
        return (-NUVO_ENODEV);
    }

    for (uint_fast32_t i = index; i < nuvo_pr->device_count - 1; i++)
    {
        nuvo_pr->device_list[i] = nuvo_pr->device_list[i + 1];
    }
    nuvo_pr->device_count--;

    nuvo_mutex_unlock(&nuvo_pr->device_mutex);

    return (0);
}

nuvo_return_t nuvo_pr_device_remove_all(const uuid_t node_id)
{
    nuvo_return_t ret;
    uint_fast16_t node_index;

    nuvo_mutex_lock(&nuvo_pr->node_mutex);
    ret = nuvo_pr_node_find(node_id, &node_index);
    if (ret < 0)
    {
        nuvo_mutex_unlock(&nuvo_pr->node_mutex);
        return (-NUVO_ENOENT);
    }

    ret = nuvo_pr_device_remove_all_index(node_index);

    nuvo_mutex_unlock(&nuvo_pr->node_mutex);

    return (ret);
}

nuvo_return_t nuvo_pr_device_remove_all_index(uint_fast16_t node_index)
{
    nuvo_mutex_lock(&nuvo_pr->device_mutex);
    for (uint_fast32_t i = 0; i < nuvo_pr->device_count;)
    {
        if (nuvo_pr->device_list[i].node_index == node_index)
        {
            for (uint_fast32_t n = i; n < nuvo_pr->device_count - 1; n++)
            {
                nuvo_pr->device_list[n] = nuvo_pr->device_list[n + 1];
            }
            nuvo_pr->device_count--;
        }
        else
        {
            i++;
        }
    }

    nuvo_mutex_unlock(&nuvo_pr->device_mutex);

    return (0);
}

void nuvo_pr_cconn_set_state(struct nuvo_pr_client_conn *conn,
                             enum nuvo_cconn_cstate      state)
{
    NUVO_ASSERT_MUTEX_HELD(&conn->cc_mutex);

    NUVO_LOG(pr, 50, "Connection %d changed state from %d to %d.",
             GET_PR_CCONN_IDX(conn), conn->cc_state, state);

    // ASSERT the state transitions are valid
    switch (state)
    {
    case NUVO_CCCS_CLOSED:
        // Any state can transition to closed
        break;

    case NUVO_CCCS_CONNECTING:
        NUVO_ASSERT(conn->cc_state == NUVO_CCCS_CLOSED);
        break;

    case NUVO_CCCS_CONNECTED:
        NUVO_ASSERT(conn->cc_state == NUVO_CCCS_CLOSED ||
                    conn->cc_state == NUVO_CCCS_CONNECTING ||
                    conn->cc_state == NUVO_CCCS_RESENDING);
        break;

    case NUVO_CCCS_ERROR:
        // Any state can transition to Error
        // Reset the resend phase here instead of everywhere error is set.
        conn->cc_resend_phase = NUVO_RESEND_NONE;
        break;

    case NUVO_CCCS_RECONNECT:
        NUVO_ASSERT(conn->cc_state == NUVO_CCCS_ERROR);
        break;

    case NUVO_CCCS_RESEND_READY:
        NUVO_ASSERT(conn->cc_state == NUVO_CCCS_RECONNECT ||
                    conn->cc_state == NUVO_CCCS_RESENDING);
        break;

    case NUVO_CCCS_RESENDING:
        NUVO_ASSERT(conn->cc_state == NUVO_CCCS_RESEND_READY);
        break;

    default:
        NUVO_ASSERT("Invalid State!");
    }

    conn->cc_state = state;

    return;
}

uint64_t cconn_alloc_count = 0;
uint64_t cconn_free_count = 0;

struct nuvo_pr_client_conn *nuvo_pr_cconn_alloc()
{
    nuvo_mutex_lock(&nuvo_pr->client_conn_mutex);
    struct nuvo_pr_client_conn *conn = nuvo_dlist_remove_head_object(
        &nuvo_pr->client_conn_free_list, struct nuvo_pr_client_conn, list_node);

    if (conn == NULL)
    {
        if (nuvo_pr->client_conn_used <
            NUVO_ARRAY_LENGTH(nuvo_pr->client_conn_table))
        {
            conn = &nuvo_pr->client_conn_table[nuvo_pr->client_conn_used++];
            // Setting cc_state directly instead of calling set_state because
            // we don't need to hold the cc_mutex during init.
            conn->cc_state = NUVO_CCCS_CLOSED;
            conn->cc_resend_phase = NUVO_RESEND_NONE;
            conn->sock_fd = -1;
            conn->cc_gen = 0;
            nuvo_dlnode_init(&conn->list_node);
            nuvo_dlist_init(&conn->req_wait_list);
            nuvo_dlist_init(&conn->req_pending_list);
            nuvo_dlist_init(&conn->req_retry_list);
            nuvo_dlist_init(&conn->open_parcel_list);
            nuvo_dlist_init(&conn->reopen_parcel_list);
            nuvo_mutex_init(&conn->cc_mutex);
        }
    }

    if (conn != NULL)
    {
        // These should be reset everytime we get a new connection
        conn->prev_close_reason = 0;
        conn->prev_close_err = 0;
        conn->conn_err_cnt = 0;
        conn->recovery_start_ts = 0;
        conn->backoff_cnt = 0;

        nuvo_dlist_insert_tail(&nuvo_pr->client_conn_active_list,
                               &conn->list_node);
        cconn_alloc_count++;
    }

    nuvo_mutex_unlock(&nuvo_pr->client_conn_mutex);

    return (conn);
}

void nuvo_pr_cconn_free(struct nuvo_pr_client_conn *conn)
{
    cconn_free_count++;
    NUVO_ASSERT(conn - nuvo_pr->client_conn_table >= 0);
    NUVO_ASSERT(conn - nuvo_pr->client_conn_table < (intptr_t)NUVO_ARRAY_LENGTH(
                    nuvo_pr->client_conn_table));

    NUVO_ASSERT(conn->cc_state == NUVO_CCCS_CLOSED);
    NUVO_ASSERT(nuvo_dlist_get_head(&conn->req_wait_list) == NULL);
    NUVO_ASSERT(nuvo_dlist_get_head(&conn->req_pending_list) == NULL);

    conn->sock_fd = -1;
    conn->cc_gen++;
    nuvo_mutex_lock(&nuvo_pr->client_conn_mutex);
    nuvo_dlist_remove(&conn->list_node); // from active list or error list
    nuvo_dlist_insert_head(&nuvo_pr->client_conn_free_list, &conn->list_node);
    nuvo_mutex_unlock(&nuvo_pr->client_conn_mutex);
}

nuvo_return_t nuvo_pr_cconn_enqueue_req(struct nuvo_pr_client_conn *conn,
                                        struct nuvo_io_request     *req,
                                        struct nuvo_dlist          *completed_list)
{
    if (conn->cc_state == NUVO_CCCS_CONNECTED)
    {
        nuvo_dlist_insert_tail(&conn->req_wait_list, &req->list_node);
        nuvo_pr_cconn_process_send(conn, completed_list);
    }
    else if ((conn->cc_state == NUVO_CCCS_CONNECTING) ||
             (conn->cc_state == NUVO_CCCS_ERROR))

    {
        // Don't try to send now, put on wait list until network is ready.
        nuvo_dlist_insert_tail(&conn->req_wait_list, &req->list_node);
    }
    else if (NUVO_PR_IS_CCONN_IN_RECOVERY(cconn))
    {
        if (nuvo_pr_is_resend_config_req(req))
        {
            // Special case for letting parcel reopen requests through.
            nuvo_dlist_insert_head(&conn->req_retry_list, &req->list_node);
            if (conn->cc_state == NUVO_CCCS_RESENDING)
            {
                nuvo_pr_cconn_process_send(conn, completed_list);
            }
        }
        else
        {
            // Don't try to send now, put on wait list until network is ready.
            nuvo_dlist_insert_tail(&conn->req_wait_list, &req->list_node);
        }
    }
    else
    {
        return (-NUVO_E_CONN_CLOSED);
    }

    return (0);
}

nuvo_return_t nuvo_pr_cconn_process_send(struct nuvo_pr_client_conn *conn,
                                         struct nuvo_dlist          *completed_list)
{
    NUVO_ASSERT_MUTEX_HELD(&conn->cc_mutex);
    NUVO_ASSERT(conn->cc_state != NUVO_CCCS_CLOSED);
    ssize_t ret;

    while (1)
    {
        // work on any current requests, when finished start any queued requests
        if (conn->send_state == NUVO_CCSS_HEADER)
        {
            if (conn->cc_state == NUVO_CCCS_RESENDING)
            {
                NUVO_ASSERT((conn->send_req->op_retry_cnt != 0) ||
                            (nuvo_pr_is_resend_config_req(conn->send_req)));

                NUVO_LOG(pr, 0,
                         "Connection Recovery - conn %d resending request %p, op type %d, attempt %d",
                         GET_PR_CCONN_IDX(conn), (void *)conn->send_req,
                         conn->send_req->operation,
                         conn->send_req->op_retry_cnt);
            }
            ssize_t ret = send(conn->sock_fd,
                               (void *)((uintptr_t)&conn->send_header +
                                        conn->send_count),
                               sizeof(conn->send_header) - conn->send_count, 0);
            int64_t l_errno = errno; // local errno, don't want to modify errno.

            if (test_fi_inject_node_rc(TEST_FI_PR_CLIENT_SEND_HEADER,
                                       nuvo_pr->pr_test_info,
                                       conn->node_desc->id, &l_errno))
            {
                ret = -1;
            }

            if (ret < 0)
            {
                if (l_errno == EINTR)
                {
                    // we were interrupted, try again
                    continue;
                }
                NUVO_ERROR_PRINT(
                    "Connection Error - conn %d terminating due to send() failure: %d",
                    GET_PR_CCONN_IDX(conn), l_errno);
                nuvo_pr_cconn_handle_error(conn, l_errno, NUVO_CCR_SEND);
                return (-NUVO_E_SEND);
            }
            else if (ret == 0)
            {
                NUVO_ASSERT(l_errno == EAGAIN || l_errno == EWOULDBLOCK);
                // can't send more on socket without blocking
                // break and continue when epoll lets us know we can send more
                break;
            }

            conn->send_count += ret;
            conn->send_total_bytes += ret;

            // check if we're done with sending the header
            NUVO_ASSERT(conn->send_count <= sizeof(conn->send_header));
            if (conn->send_count == sizeof(conn->send_header))
            {
                conn->send_count = 0;
                // finished sending the header, move onto data if there is any
                if ((conn->send_req->operation == NUVO_OP_WRITE) ||
                    (conn->send_req->operation == NUVO_OP_READ_VERIFY))
                {
                    // write and read verify send the data hashes.
                    // write hashes verify the data transmitted across the wire.
                    // read hashes verify the data read from disk.
                    conn->send_state = NUVO_CCSS_HASHESDATA;
                    conn->send_req->rw.hashes_iovec.iov_base =
                        conn->send_req->rw.block_hashes;
                    conn->send_req->rw.hashes_iovec.iov_len =
                        NUVO_HASH_BYTES * conn->send_req->rw.block_count;
                }
                else
                {
                    // request has no data to send, put on pending list
                    nuvo_dlist_insert_head(&conn->req_pending_list,
                                           &conn->send_req->list_node);
                    conn->send_req = NULL;

                    conn->send_state = NUVO_CCSS_IDLE;
                }
            }
        }
        else if (conn->send_state == NUVO_CCSS_HASHESDATA)
        {
            // find the iovec we're in, and the offset into that iovec
            uint_fast16_t iov_index;
            uint_fast32_t offset;
            struct iovec *iovs = &conn->send_req->rw.hashes_iovec;
            if (conn->send_count < iovs->iov_len)
            {
                iov_index = 0;
                offset = conn->send_count;
            }
            else
            {
                iov_index = 1 + (conn->send_count - iovs->iov_len)
                            / NUVO_BLOCK_SIZE;
                offset = (conn->send_count - iovs->iov_len) % NUVO_BLOCK_SIZE;
            }

            // save a copy of the original iovec
            struct iovec orig_iovec = iovs[iov_index];

            // update iovec to point to the current position in the recv stream
            iovs[iov_index].iov_base =
                (void *)((uintptr_t)iovs[iov_index].iov_base + offset);
            iovs[iov_index].iov_len -= offset;

            // send as much as we can
            ret = writev(conn->sock_fd, &iovs[iov_index],
                         conn->send_req->rw.block_count + 1 - iov_index);
            int64_t l_errno = errno;

            // restore the original iovec
            iovs[iov_index] = orig_iovec;

            if (test_fi_inject_node_rc(TEST_FI_PR_CLIENT_SEND_DATA,
                                       nuvo_pr->pr_test_info,
                                       conn->node_desc->id, &l_errno))
            {
                ret = -1;
            }

            // check for errors
            if (ret < 0)
            {
                if (l_errno == EINTR)
                {
                    // we were interrupted, try again
                    continue;
                }
                else if (l_errno == EAGAIN || l_errno == EWOULDBLOCK)
                {
                    // can't send more on socket without blocking
                    // break and continue when epoll lets us know when can send more
                    break;
                }
                NUVO_ERROR_PRINT(
                    "Connection Error - conn %d terminating due to writev() failure: %d",
                    GET_PR_CCONN_IDX(conn), l_errno);
                nuvo_pr_cconn_handle_error(conn, l_errno, NUVO_CCR_WRITEV);
                return (-NUVO_E_SEND);
            }
            else if (ret == 0)
            {
                NUVO_ASSERT(l_errno == EAGAIN || l_errno == EWOULDBLOCK);
                // can't send more on socket without blocking
                // break and continue when epoll lets us know when can send more
                break;
            }

            conn->send_count += ret;
            conn->send_total_bytes += ret;

            // check if we're done with sending the data
            NUVO_ASSERT(conn->send_count <= conn->send_req->rw.block_count *
                        NUVO_BLOCK_SIZE + iovs->iov_len);
            if (conn->send_count == conn->send_req->rw.block_count *
                NUVO_BLOCK_SIZE + iovs->iov_len)
            {
                // we've finished sending the data, put request on pending list
                conn->send_count = 0;
                nuvo_dlist_insert_head(&conn->req_pending_list,
                                       &conn->send_req->list_node);
                conn->send_req = NULL;

                conn->send_state = NUVO_CCSS_IDLE;
            }
        }
        else if (conn->send_state == NUVO_CCSS_IDLE)
        {
            // check if we have queued requests, if so pull one and start working on it
            if (conn->cc_state == NUVO_CCCS_CONNECTED)
            {
                conn->send_req = nuvo_dlist_remove_head_object(
                    &conn->req_wait_list, struct nuvo_io_request,
                    list_node);
            }
            else if (conn->cc_state == NUVO_CCCS_RESENDING)
            {
                uint32_t retry_cnt_max = 100;

                conn->send_req = nuvo_dlist_remove_head_object(
                    &conn->req_retry_list, struct nuvo_io_request,
                    list_node);

                if (conn->send_req)
                {
                    // We could be resending in flight ops or resending
                    // configuration operations like parcel reopens.
                    // If we are in the config phase, only process config ops.
                    if (conn->cc_resend_phase == NUVO_RESEND_CONFIG)
                    {
                        if (!nuvo_pr_is_resend_config_req(conn->send_req))
                        {
                            // All parcel reopens are put at the front of the
                            // retry list.  The first request we find that is
                            // not a parcel reopen means we are done. Put this
                            // request back and stop processing the retry list.
                            nuvo_dlist_insert_head(&conn->req_retry_list,
                                                   &conn->send_req->list_node);
                            conn->send_req = NULL;
                            break;
                        }
                    }

                    // If this op is having serious problems, give up.
                    if (conn->send_req->op_retry_cnt > retry_cnt_max)
                    {
                        conn->send_req->status = -NUVO_E_IO_RETRY_CNT_EXCEEDED;
                        nuvo_dlist_insert_tail(completed_list,
                                               &conn->send_req->list_node);
                        return (-NUVO_E_SEND);
                    }
                    // Bail out if we don't currently support retries for this op
                    if (!nuvo_pr_is_retriable_req(conn->send_req))
                    {
                        conn->send_req->status = -NUVO_E_IO_RETRY_CNT_EXCEEDED;
                        nuvo_dlist_insert_tail(completed_list,
                                               &conn->send_req->list_node);
                        return (-NUVO_E_SEND);
                    }
                }
            }
            else
            {
                conn->send_req = NULL;
            }

            if (conn->send_req == NULL)
            {
                // nothing to send, exit function
                break;
            }

            // populate the header data here
            memset(&conn->send_header, 0, sizeof(conn->send_header));
            conn->send_header.operation = conn->send_req->operation;
            conn->send_header.op_retry_cnt = conn->send_req->op_retry_cnt;

            conn->send_header.tag.req_index = conn->send_req -
                                              nuvo_pr->client_req_pool.req_table;
            conn->send_header.tag.conn_index = conn -
                                               nuvo_pr->client_conn_table;
            conn->send_header.tag.node_index = conn->node_desc -
                                               nuvo_pr->node_table;

            switch (conn->send_header.operation)
            {
            case NUVO_OP_READ:
            case NUVO_OP_READ_VERIFY:
            case NUVO_OP_WRITE:
                conn->send_header.rw.parcel_desc =
                    conn->send_req->rw.native_parcel_desc;
                conn->send_header.rw.block_offset =
                    conn->send_req->rw.block_offset;
                conn->send_header.rw.block_count =
                    conn->send_req->rw.block_count;
                conn->send_header.rw.io_origin = conn->send_req->rw.io_origin;
                break;

            case NUVO_OP_OPEN:
                uuid_copy(conn->send_header.open.parcel_uuid,
                          conn->send_req->open.parcel_uuid);
                uuid_copy(conn->send_header.open.device_uuid,
                          conn->send_req->open.device_uuid);
                uuid_copy(conn->send_header.open.volume_uuid,
                          conn->send_req->open.volume_uuid);
                break;

            case NUVO_OP_CLOSE:
                conn->send_header.close.parcel_desc =
                    conn->send_req->close.native_parcel_desc;
                break;

            case NUVO_OP_ALLOC:
                uuid_copy(conn->send_header.alloc.parcel_uuid,
                          conn->send_req->alloc.parcel_uuid);
                uuid_copy(conn->send_header.alloc.device_uuid,
                          conn->send_req->alloc.device_uuid);
                uuid_copy(conn->send_header.alloc.volume_uuid,
                          conn->send_req->alloc.volume_uuid);
                break;

            case NUVO_OP_FREE:
                uuid_copy(conn->send_header.free.parcel_uuid,
                          conn->send_req->free.parcel_uuid);
                uuid_copy(conn->send_header.free.device_uuid,
                          conn->send_req->free.device_uuid);
                uuid_copy(conn->send_header.free.volume_uuid,
                          conn->send_req->free.volume_uuid);
                break;

            case NUVO_OP_DEV_INFO:
                uuid_copy(conn->send_header.dev_info.device_uuid,
                          conn->send_req->dev_info.device_uuid);
                break;

            default:
                NUVO_ASSERT(0);
            }
            // generate hash for filled header
            conn->send_header.hash = nuvo_hash(&conn->send_header, offsetof(
                                                   struct nuvo_net_req_header,
                                                   hash));

            conn->send_state = NUVO_CCSS_HEADER;
        }
        else
        {
            // invalid state
            NUVO_PANIC("Invalid client connection send state %d.",
                       conn->send_state);
        }
    }

    return (0);
}

nuvo_return_t nuvo_pr_cconn_process_recv(struct nuvo_pr_client_conn *conn,
                                         struct nuvo_dlist          *completed_list)
{
    struct nuvo_io_request *req;

    NUVO_ASSERT((conn->cc_state == NUVO_CCCS_CONNECTED) ||
                (conn->cc_state == NUVO_CCCS_RESENDING));
    ssize_t ret;

    while (1)
    {
        if (conn->recv_state == NUVO_CCRS_HEADER)
        {
            ret = recv(conn->sock_fd,
                       (void *)((uintptr_t)&conn->recv_header + conn->recv_count),
                       sizeof(conn->recv_header) - conn->recv_count, 0);
            int64_t l_errno = errno;

            if (test_fi_inject_node_rc(TEST_FI_PR_CLIENT_RECV_HEADER,
                                       nuvo_pr->pr_test_info,
                                       conn->node_desc->id, &l_errno))
            {
                ret = -1;
            }
            if (ret < 0)
            {
                if (l_errno == EAGAIN || l_errno == EWOULDBLOCK)
                {
                    // can't receive more on socket without blocking
                    // break and continue when epoll lets us know when can receive more
                    break;
                }
                else if (l_errno == EINTR)
                {
                    // we were interrupted, try again
                    continue;
                }
                else
                {
                    NUVO_ERROR_PRINT(
                        "Connection Error - conn %d terminating due to recv() failure: %d",
                        GET_PR_CCONN_IDX(conn), l_errno);
                    nuvo_pr_cconn_handle_error(conn, l_errno, NUVO_CCR_RECV);
                    return (-NUVO_E_RECV);
                }
            }
            else if (ret == 0)
            {
                // connection closed remotely
                NUVO_ERROR_PRINT(
                    "Connection Error - conn %d closed in the middle of recv() request: %d",
                    GET_PR_CCONN_IDX(conn), l_errno);
                nuvo_pr_cconn_handle_error(conn, l_errno,
                                           NUVO_CCR_RECV_NO_DATA);
                return (-NUVO_E_CONN_CLOSED);
            }

            conn->recv_count += ret;
            conn->recv_total_bytes += ret;

            // if we've received the entire header, process it
            if (conn->recv_count == sizeof(conn->recv_header))
            {
                conn->recv_count = 0;
                // verify header hash
                if (conn->recv_header.hash !=
                    nuvo_hash(&conn->recv_header,
                              offsetof(struct nuvo_net_resp_header, hash)))
                {
                    NUVO_ERROR_PRINT(
                        "Connection Error - conn %d terminating due to invalid header hash.",
                        GET_PR_CCONN_IDX(conn));
                    nuvo_pr_cconn_handle_error(conn, NUVO_E_BAD_HASH,
                                               NUVO_CCR_HEADER_HASH);
                    return (-NUVO_E_BAD_HASH);
                }

                if ((conn->recv_header.tag.req_index >=
                     NUVO_ARRAY_LENGTH(nuvo_pr->client_req_pool.req_table)) ||
                    (conn->recv_header.tag.conn_index != conn -
                     nuvo_pr->client_conn_table) ||
                    (conn->recv_header.tag.node_index != conn->node_desc -
                     nuvo_pr->node_table))
                {
                    // invalid tag
                    NUVO_ERROR_PRINT(
                        "Connection Error - conn %d terminating due to invalid header tag.",
                        GET_PR_CCONN_IDX(conn));
                    nuvo_pr_cconn_handle_error(conn, NUVO_E_BAD_TAG,
                                               NUVO_CCR_HEADER_TAG);
                    return (-NUVO_E_BAD_TAG);
                }

                // get reference to the request
                req = nuvo_pr->client_req_pool.req_table +
                      conn->recv_header.tag.req_index;

                if (req->op_retry_cnt > 0)
                {
                    NUVO_LOG(pr, 10,
                             "Connection Recovery - conn %d received ACK for a retried operation %p. Retried %d times.",
                             GET_PR_CCONN_IDX(conn), (void *)req,
                             req->op_retry_cnt);
                }

                switch (req->operation)
                {
                case NUVO_OP_READ:
                case NUVO_OP_READ_VERIFY:
                    // read operation will have hashes and data coming next
                    conn->recv_req = req;
                    conn->recv_state = NUVO_CCRS_HASHESDATA;
                    req->rw.hashes_iovec.iov_base = req->rw.block_hashes;
                    req->rw.hashes_iovec.iov_len = NUVO_HASH_BYTES *
                                                   req->rw.block_count;
                    break;

                case NUVO_OP_WRITE:
                    // remove from pending list
                    nuvo_dlist_remove(&req->list_node);
                    req->status = conn->recv_header.status;
                    nuvo_dlist_insert_tail(completed_list, &req->list_node);
                    break;

                case NUVO_OP_OPEN:
                    req->status = conn->recv_header.status;

                    req->open.parcel_desc = conn->recv_header.open.parcel_desc;

                    if ((req->status >= 0) ||
                        (req->status == -NUVO_E_PARCEL_ALREADY_OPEN))
                    {
                        // After open completes successfully, cache some info
                        // about the parcel.
                        ret = nuvo_pr_add_parcel_open_info(req, conn);
                        if (ret < 0)
                        {
                            // We failed to allocate memory.  Set status to
                            // failure and maybe we'll succeed on a retry.
                            req->status = ret;
                        }
                    }
                    // remove from pending list
                    nuvo_dlist_remove(&req->list_node);
                    nuvo_dlist_insert_tail(completed_list, &req->list_node);
                    break;

                case NUVO_OP_CLOSE:
                    // remove from pending list
                    nuvo_dlist_remove(&req->list_node);
                    req->status = conn->recv_header.status;

                    if ((req->status >= 0) ||
                        (req->status == -NUVO_E_PARCEL_ALREADY_CLOSED))
                    {
                        nuvo_pr_remove_parcel_open_info(req->close.parcel_desc,
                                                        conn);
                    }
                    nuvo_dlist_insert_tail(completed_list, &req->list_node);
                    break;

                case NUVO_OP_ALLOC:
                    req->status = conn->recv_header.status;

                    if (req->status >= 0)
                    {
                        uuid_copy(req->alloc.parcel_uuid,
                                  conn->recv_header.alloc.parcel_uuid);
                    }

                    // remove from pending list
                    nuvo_dlist_remove(&req->list_node);
                    nuvo_dlist_insert_tail(completed_list, &req->list_node);
                    break;

                case NUVO_OP_FREE:
                    // remove from pending list
                    nuvo_dlist_remove(&req->list_node);
                    req->status = conn->recv_header.status;
                    nuvo_dlist_insert_tail(completed_list, &req->list_node);
                    break;

                case NUVO_OP_DEV_INFO:
                    req->status = conn->recv_header.status;

                    if (req->status >= 0)
                    {
                        req->dev_info.device_size =
                            conn->recv_header.dev_info.device_size;
                        req->dev_info.parcel_size =
                            conn->recv_header.dev_info.parcel_size;
                        req->dev_info.device_type =
                            conn->recv_header.dev_info.device_type;
                    }

                    // remove from pending list
                    nuvo_dlist_remove(&req->list_node);
                    nuvo_dlist_insert_tail(completed_list, &req->list_node);
                    break;

                default:
                    NUVO_PANIC("Invalid request operation %d.", req->operation);
                }
            }
        }
        else if (conn->recv_state == NUVO_CCRS_HASHESDATA)
        {
            // only read and read verify requests receive hashes/data
            NUVO_ASSERT(conn->recv_req->operation == NUVO_OP_READ ||
                        conn->recv_req->operation == NUVO_OP_READ_VERIFY);
            // find the iovec we're in, and the offset into that iovec
            uint_fast16_t iov_index;
            uint_fast32_t offset;
            struct iovec *iovs = &conn->recv_req->rw.hashes_iovec;
            if (conn->recv_count < iovs->iov_len)
            {
                iov_index = 0;
                offset = conn->recv_count;
            }
            else
            {
                iov_index = 1 + (conn->recv_count - iovs->iov_len) /
                            NUVO_BLOCK_SIZE;
                offset = (conn->recv_count - iovs->iov_len) % NUVO_BLOCK_SIZE;
            }

            // save a copy of the original iovec
            struct iovec orig_iovec = iovs[iov_index];

            // update iovec to point to the current position in the recv stream
            iovs[iov_index].iov_base =
                (void *)((uintptr_t)iovs[iov_index].iov_base + offset);
            iovs[iov_index].iov_len -= offset;

            // recv as much as we can
            ret = readv(conn->sock_fd, &iovs[iov_index],
                        conn->recv_req->rw.block_count + 1 - iov_index);
            int64_t l_errno = errno;
            // restore the original iovec
            iovs[iov_index] = orig_iovec;

            if (test_fi_inject_node_rc(TEST_FI_PR_CLIENT_RECV_DATA,
                                       nuvo_pr->pr_test_info,
                                       conn->node_desc->id, &l_errno))
            {
                ret = -1;
            }
            if (ret < 0)
            {
                if (l_errno == EAGAIN || l_errno == EWOULDBLOCK)
                {
                    // can't receive more on socket without blocking
                    // break and continue when epoll lets us know when can receive more
                }
                else if (l_errno == EINTR)
                {
                    // we were interrupted, try again
                    continue;
                }
                else
                {
                    NUVO_ERROR_PRINT(
                        "Connection Error - conn %d terminating due to readv() failure: %d",
                        GET_PR_CCONN_IDX(conn), l_errno);
                    nuvo_pr_cconn_handle_error(conn, l_errno, NUVO_CCR_READV);
                    return (-NUVO_E_RECV);
                }
                break;
            }
            else if (ret == 0)
            {
                // connection has been closed
                NUVO_ERROR_PRINT(
                    "Connection Error - conn %d closed in the middle of a request: %d",
                    GET_PR_CCONN_IDX(conn), l_errno);
                nuvo_pr_cconn_handle_error(conn, l_errno,
                                           NUVO_CCR_READV_NO_DATA);
                return (-NUVO_E_CONN_CLOSED);
            }

            conn->recv_count += ret;
            conn->recv_total_bytes += ret;

            // check if we're done with receiving the data
            NUVO_ASSERT(conn->recv_count <= conn->recv_req->rw.block_count *
                        NUVO_BLOCK_SIZE + iovs->iov_len);
            if (conn->recv_count == conn->recv_req->rw.block_count *
                NUVO_BLOCK_SIZE + iovs->iov_len)
            {
                req = conn->recv_req;
                // verify hashes
                for (uint_fast32_t i = 0; i < req->rw.block_count; i++)
                {
                    if (req->rw.block_hashes[i] != nuvo_hash(
                            req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE))
                    {
                        NUVO_PANIC(
                            "Connection Error - conn %d terminating due to invalid data hash.",
                            GET_PR_CCONN_IDX(conn));
                        nuvo_pr_cconn_handle_error(conn, NUVO_E_BAD_HASH,
                                                   NUVO_CCR_DATA_HASH);
                        return (-NUVO_E_BAD_HASH);
                    }
                }

                // we've finished recving the data, complete the request
                // remove from pending list
                nuvo_dlist_remove(&conn->recv_req->list_node);
                conn->recv_req = NULL;

                req->status = 0; // completed successfully
                nuvo_dlist_insert_tail(completed_list, &req->list_node);

                conn->recv_count = 0;
                conn->recv_state = NUVO_CCRS_HEADER;
            }
        }
        else
        {
            // invalid state
            NUVO_PANIC("Invalid client connection receive state %d.",
                       conn->recv_state);
        }
    }

    return (0);
}

nuvo_return_t nuvo_pr_cconn_open(struct nuvo_pr_client_conn *conn, struct
                                 nuvo_pr_node_desc *node_desc)
{
    int ret;

    NUVO_ASSERT((conn->cc_state == NUVO_CCCS_CLOSED) ||
                (conn->cc_state == NUVO_CCCS_RECONNECT));

    conn->send_state = NUVO_CCSS_IDLE;
    conn->send_req = NULL;
    conn->send_count = 0;
    conn->send_total_bytes = 0;

    conn->recv_state = NUVO_CCRS_HEADER;
    conn->recv_req = NULL;
    conn->recv_count = 0;
    conn->recv_total_bytes = 0;

    // create a socket
    conn->sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (conn->sock_fd < 0)
    {
        // TODO: error codes
        return (-NUVO_ENOMEM);
    }

    // disable Nagle algorithm
    int flag = 1;
    ret = setsockopt(conn->sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag,
                     sizeof(flag));
    if (ret == -1)
    {
        close(conn->sock_fd);
        return (-NUVO_E_SOCK_OPT);
    }

    // setup address
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(node_desc->port);
    ret = inet_pton(AF_INET, node_desc->address, &addr.sin_addr);
    if (ret != 1)
    {
        close(conn->sock_fd);
        conn->sock_fd = -1;
        // TODO: error codes
        return (-NUVO_EINVAL);
    }

    conn->node_desc = node_desc;

    // begin connecting socket
    ret = connect(conn->sock_fd, (struct sockaddr *)&addr, sizeof(addr));
    int64_t l_errno = errno;

    if (ret == 0)
    {
        // Handle state transitions differently for a new connection
        if (conn->cc_state == NUVO_CCCS_CLOSED)
        {
            NUVO_LOG(pr, 50, "conn %d socket connect success",
                     GET_PR_CCONN_IDX(conn));
            nuvo_pr_cconn_set_state(conn, NUVO_CCCS_CONNECTED);
        }
        else if (conn->cc_state == NUVO_CCCS_RECONNECT)
        {
            NUVO_LOG(pr, 50,
                     "Connection Recovery - conn %d socket reconnect success",
                     GET_PR_CCONN_IDX(conn));
            nuvo_pr_cconn_set_state(conn, NUVO_CCCS_RESEND_READY);
        }
    }
    else if ((ret < 0) && (l_errno == EINPROGRESS))
    {
        // Handle state transitions differently for a new connection
        if (conn->cc_state == NUVO_CCCS_CLOSED)
        {
            // connection is being established
            nuvo_pr_cconn_set_state(conn, NUVO_CCCS_CONNECTING);
        }
        else if (conn->cc_state == NUVO_CCCS_RECONNECT)
        {
            // Wait for epoll to tell us we're ready.
            NUVO_LOG(pr, 50,
                     "Connection Recovery - conn %d socket reconnect returned EINPROGRESS, will wait for epoll notification.",
                     GET_PR_CCONN_IDX(conn));
        }
    }
    else
    {
        // something went badly wrong
        close(conn->sock_fd);
        conn->sock_fd = -1;
        // TODO: error codes
        return (-NUVO_E_CONNECT);
    }

    // Add to epoll for healthy or unhealthy (aka recovering) connections
    if (conn->cc_state == NUVO_CCCS_CONNECTING)
    {
        ret = nuvo_pr_cconn_epoll_add(conn, nuvo_pr->client_epoll_fd);
    }
    else if (conn->cc_state == NUVO_CCCS_RECONNECT)
    {
        ret = nuvo_pr_cconn_epoll_add(conn, nuvo_pr->cm_info.recovery_epoll_fd);
    }

    if (ret < 0)
    {
        close(conn->sock_fd);
        conn->sock_fd = -1;
        // TODO: error codes
        return (-NUVO_E_EPOLL_CTL);
    }

    return (0);
}

void nuvo_pr_cconn_handle_error(struct nuvo_pr_client_conn *conn,
                                int64_t                     close_err,
                                enum nuvo_conn_close_reason close_reason)
{
    NUVO_ASSERT_MUTEX_HELD(&conn->cc_mutex);

    if (conn->cc_state == NUVO_CCCS_CLOSED)
    {
        NUVO_LOG(pr, 0,
                 "Connection Error - conn %d received error %d while in closed state.",
                 GET_PR_CCONN_IDX(conn), close_err);
        return;
    }
    if (conn->cc_state == NUVO_CCCS_ERROR)
    {
        // We've already notified the conn_mgr about this error.
        // Don't need to trigger any more work, just return.
        return;
    }

    // For all other states, set the error.  We inform the connection
    // manager of the error if the connection manager isn't already
    // trying to recover from an error on this connection.
    conn->prev_close_reason = close_reason;
    conn->prev_close_err = close_err;

    if ((conn->cc_state == NUVO_CCCS_CONNECTING) ||
        (conn->cc_state == NUVO_CCCS_CONNECTED))
    {
        NUVO_LOG(pr, 0,
                 "Connection Error - conn %d encountered error %d while in state %d, notifying connection manager thread for recovery.",
                 GET_PR_CCONN_IDX(conn), close_err, conn->cc_state);

        // Move the connection from the active to the error list and send a
        // signal to the conn_mgr thread to do some work.

        // Move from active to error list
        nuvo_mutex_lock(&nuvo_pr->client_conn_mutex);
        nuvo_dlist_remove(&conn->list_node);
        nuvo_dlist_insert_head(&nuvo_pr->client_conn_error_list,
                               &conn->list_node);
        nuvo_mutex_unlock(&nuvo_pr->client_conn_mutex);

        nuvo_pr_cconn_set_state(conn, NUVO_CCCS_ERROR);
        conn->conn_err_cnt++;

        nuvo_mutex_lock(&nuvo_pr->cm_info.cm_work_mutex);
        nuvo_pr->cm_info.conn_recovery_cnt++;
        nuvo_cond_signal(&nuvo_pr->cm_info.cm_work_cv);
        nuvo_mutex_unlock(&nuvo_pr->cm_info.cm_work_mutex);
    }
    else if (NUVO_PR_IS_CCONN_IN_RECOVERY(cconn))
    {
        // We encountered an error while recovering from an error.
        // Setting the connection state to error is sufficient since the
        // connection manager is already working on this troubled connection.
        nuvo_pr_cconn_set_state(conn, NUVO_CCCS_ERROR);
        conn->conn_err_cnt++;
    }

    return;
}

void nuvo_pr_cconn_shutdown(struct nuvo_pr_client_conn *conn,
                            struct nuvo_dlist          *completed_list,
                            int64_t                     close_err,
                            enum nuvo_conn_close_reason close_reason)
{
    int ret;
    struct nuvo_pr_node_desc *node_desc;
    int epoll_fd;

    if (conn->cc_state == NUVO_CCCS_CLOSED)
    {
        // this connection has already been shutdown
        NUVO_LOG(pr, 0,
                 "Connection Shutdown - conn %d (client) shutdown called on already shutdown connection.",
                 GET_PR_CCONN_IDX(conn));
        return;
    }

    if ((conn->cc_state == NUVO_CCCS_CONNECTING) ||
        (conn->cc_state == NUVO_CCCS_CONNECTED))
    {
        epoll_fd = nuvo_pr->client_epoll_fd;
    }
    else
    {
        epoll_fd = nuvo_pr->cm_info.recovery_epoll_fd;
    }


    // change state
    nuvo_pr_cconn_set_state(conn, NUVO_CCCS_CLOSED);

    conn->prev_close_reason = close_reason;
    conn->prev_close_err = close_err;
    conn->recv_state = NUVO_CCRS_HEADER;
    conn->recv_count = 0;
    conn->recv_total_bytes = 0;

    if (conn->recv_req != NULL)
    {
        conn->recv_req->status = close_err;
        nuvo_dlist_insert_tail(completed_list, &conn->recv_req->list_node);
        conn->recv_req = NULL;
    }

    conn->send_state = NUVO_CCSS_IDLE;
    conn->send_count = 0;
    conn->send_total_bytes = 0;
    if (conn->send_req != NULL)
    {
        conn->send_req->status = close_err;
        nuvo_dlist_insert_tail(completed_list, &conn->send_req->list_node);
        conn->send_req = NULL;
    }

    // remove from epoll
    ret = nuvo_pr_cconn_epoll_remove(conn, epoll_fd);

    if (ret == -1)
    {
        // TODO: since we're shutting down, okay to just ignore this?
    }

    // shutdown socket
    close(conn->sock_fd);
    conn->sock_fd = -1;

    // abort pending requests
    struct nuvo_io_request *req;
    while ((req = nuvo_dlist_remove_head_object(&conn->req_pending_list, struct
                                                nuvo_io_request, list_node)) != NULL)
    {
        req->status = -NUVO_E_CONN_CLOSED;
        nuvo_dlist_insert_tail(completed_list, &req->list_node);
    }

    while ((req = nuvo_dlist_remove_head_object(&conn->req_wait_list, struct
                                                nuvo_io_request, list_node)) != NULL)
    {
        req->status = -NUVO_E_CONN_CLOSED;
        nuvo_dlist_insert_tail(completed_list, &req->list_node);
    }

    while ((req = nuvo_dlist_remove_head_object(&conn->req_retry_list, struct
                                                nuvo_io_request, list_node)) != NULL)
    {
        req->status = -NUVO_E_CONN_CLOSED;
        nuvo_dlist_insert_tail(completed_list, &req->list_node);
    }

    // attempt to unlink connection from node
    // if node is locked, allow deferred removal by whoever has lock
    node_desc = conn->node_desc;
    if (nuvo_mutex_trylock(&node_desc->nd_mutex))
    {
        if (node_desc->conn != conn)
        {
            // this should never happen
            NUVO_PANIC("Node to connection link invalid.");
        }
        nuvo_pr_cconn_free(conn);
        node_desc->conn = NULL;

        // remove existing pdefs
        nuvo_pr_pdef_remove_all(node_desc);

        nuvo_mutex_unlock(&node_desc->nd_mutex);
    }

    return;
}

struct nuvo_pr_server_conn *nuvo_pr_sconn_alloc()
{
    nuvo_mutex_lock(&nuvo_pr->server_conn_mutex);
    struct nuvo_pr_server_conn *conn = nuvo_dlist_remove_head_object(
        &nuvo_pr->server_conn_free_list, struct nuvo_pr_server_conn, list_node);

    if (conn == NULL)
    {
        if (nuvo_pr->server_conn_used < NUVO_ARRAY_LENGTH(
                nuvo_pr->server_conn_table))
        {
            conn = &nuvo_pr->server_conn_table[nuvo_pr->server_conn_used++];
            conn->sc_state = NUVO_SCCS_CLOSED;
            conn->sock_fd = -1;
            conn->sc_gen = 0;
            nuvo_dlnode_init(&conn->list_node);
            nuvo_dlist_init(&conn->req_ready_list);
            nuvo_mutex_init(&conn->sc_mutex);
        }
    }

    if (conn != NULL)
    {
        nuvo_dlist_insert_tail(&nuvo_pr->server_conn_active_list,
                               &conn->list_node);
    }

    nuvo_mutex_unlock(&nuvo_pr->server_conn_mutex);

    return (conn);
}

void nuvo_pr_sconn_free(struct nuvo_pr_server_conn *conn)
{
    NUVO_ASSERT(conn - nuvo_pr->server_conn_table >= 0);
    NUVO_ASSERT(conn - nuvo_pr->server_conn_table <
                (intptr_t)NUVO_ARRAY_LENGTH(nuvo_pr->server_conn_table));

    NUVO_ASSERT(conn->sc_state == NUVO_SCCS_CLOSED);
    NUVO_ASSERT(nuvo_dlist_get_head(&conn->req_ready_list) == NULL);

    conn->sock_fd = -1;
    conn->sc_gen++;

    nuvo_mutex_lock(&nuvo_pr->server_conn_mutex);
    nuvo_dlist_remove(&conn->list_node); // from active list
    nuvo_dlist_insert_head(&nuvo_pr->server_conn_free_list, &conn->list_node);
    nuvo_mutex_unlock(&nuvo_pr->server_conn_mutex);
}

void nuvo_pr_sconn_req_comp_cb(struct nuvo_io_request *req)
{
    struct nuvo_pr_server_conn *conn = req->sconn;

    nuvo_mutex_lock(&conn->sc_mutex);

    // enqueue the completed request for sending, call send processing
    // decrement outstanding reqs on connection
    conn->req_outstanding--;
    if (conn->sc_state == NUVO_SCCS_CONNECTED)
    {
        nuvo_dlist_insert_head(&conn->req_ready_list, &req->list_node);
        nuvo_pr_sconn_process_send(conn);
        nuvo_mutex_unlock(&conn->sc_mutex);

        return;
    }
    else if (conn->sc_state == NUVO_SCCS_CLOSED)
    {
        NUVO_PANIC("Request completion received on closed connection.");
    }

    // The connection is in the process of closing. Free the req/bufs.
    if ((req->operation == NUVO_OP_WRITE) || (req->operation == NUVO_OP_READ) ||
        (req->operation == NUVO_OP_READ_VERIFY))
    {
        nuvo_pr_buf_free_req(&nuvo_pr->server_buf_pool, req);
        nuvo_pr_req_free(&nuvo_pr->server_req_pool, req);
    }

    if (conn->sc_state == NUVO_SCCS_CLOSING)
    {
        if (conn->req_outstanding == 0 && conn->recv_state == NUVO_SCRS_HEADER)
        {
            conn->sc_state = NUVO_SCCS_CLOSED;
            nuvo_pr_sconn_free(conn);
            NUVO_LOG(pr, 0,
                     "Connection Shutdown - conn %d outstanding requests completed, connection freed - Success",
                     GET_PR_SCONN_IDX(conn));
        }
    }
    else if (conn->sc_state == NUVO_SCCS_ERROR)
    {
        NUVO_LOG(pr, 0,
                 "Connection Error - conn %d received completion callback while in error state",
                 GET_PR_SCONN_IDX(conn));
    }

    nuvo_mutex_unlock(&conn->sc_mutex);
}

// Prototype to allow the inline to compile.
void nuvo_pr_print_req_buf_stats();

// This will not print unless pr log level is set to a high value
inline void nuvo_pr_print_req_buf_stats()
{
    NUVO_LOG_CAN_SUPPRESS(pr, 90, SUP_GRP_PR_REQ_BUF_USED, 1,
                          "Usage stats: Client reqs used: %d , bufs used: %d ; Server reqs used: %d , bufs used: %d",
                          NUVO_ARRAY_LENGTH(nuvo_pr->client_req_pool.req_table)
                          - nuvo_pr->client_req_pool.req_free_cnt,
                          NUVO_ARRAY_LENGTH(nuvo_pr->client_buf_pool.buf_table)
                          - nuvo_pr->client_buf_pool.buf_free_cnt,
                          NUVO_ARRAY_LENGTH(nuvo_pr->server_req_pool.req_table)
                          - nuvo_pr->server_req_pool.req_free_cnt,
                          NUVO_ARRAY_LENGTH(nuvo_pr->server_buf_pool.buf_table)
                          - nuvo_pr->server_buf_pool.buf_free_cnt);
}

void nuvo_pr_sconn_buf_alloc_cb(struct nuvo_pr_buf_alloc *alloc)
{
    struct nuvo_pr_server_conn *conn =
        (struct nuvo_pr_server_conn *)alloc->tag.ptr;

    struct nuvo_io_request *req = alloc->req;
    struct nuvo_dlist       submit_list;

    nuvo_mutex_lock(&conn->sc_mutex);

    if (conn->sc_state == NUVO_SCCS_CLOSING)
    {
        nuvo_pr_buf_free_req(&nuvo_pr->server_buf_pool, req);
        nuvo_pr_req_free(&nuvo_pr->server_req_pool, req);
        conn->recv_state = NUVO_SCRS_HEADER;

        if (conn->req_outstanding == 0)
        {
            conn->sc_state = NUVO_SCCS_CLOSED;
            nuvo_pr_sconn_free(conn);
            NUVO_LOG(pr, 0,
                     "Connection Shutdown - conn %d pending buf allocation requests completed - Success",
                     GET_PR_SCONN_IDX(conn));
        }
    }
    else if (conn->sc_state == NUVO_SCCS_CLOSED)
    {
        NUVO_PANIC("Received buf alloc callback on closed connection.");
    }
    else if (conn->sc_state == NUVO_SCCS_ERROR)
    {
        // The conn_mgr will transition to closing, don't change state.
        NUVO_LOG(pr, 0,
                 "Connection Manager - conn %d received buf alloc callback while in error state.",
                 GET_PR_SCONN_IDX(conn));

        if (conn->recv_req == req)
        {
            conn->recv_req = NULL;
        }
        else
        {
            NUVO_ASSERT(!"Received buf alloc callback for unexpected req");
        }
        nuvo_pr_buf_free_req(&nuvo_pr->server_buf_pool, req);
        nuvo_pr_req_free(&nuvo_pr->server_req_pool, req);
        conn->recv_state = NUVO_SCRS_HEADER;
    }
    else if (conn->sc_state == NUVO_SCCS_CONNECTED)
    {
        switch (conn->recv_header.operation)
        {
        case NUVO_OP_READ:
            // reads are ready to go
            nuvo_dlist_init(&submit_list);
            nuvo_dlist_insert_head(&submit_list, &req->list_node);

            conn->recv_req = NULL;
            conn->recv_count = 0;
            conn->recv_state = NUVO_SCRS_HEADER;

            // track outstanding requests
            conn->req_outstanding++;

            nuvo_mutex_unlock(&conn->sc_mutex);
            nuvo_pm_submit(&submit_list);
            nuvo_mutex_lock(&conn->sc_mutex);
            break;

        case NUVO_OP_WRITE:
        case NUVO_OP_READ_VERIFY:
            // writes and read verify need to receive hashes next
            conn->recv_state = NUVO_SCRS_HASHESDATA;
            req->rw.hashes_iovec.iov_base = req->rw.block_hashes;
            req->rw.hashes_iovec.iov_len = NUVO_HASH_BYTES *
                                           req->rw.block_count;
            break;

        default:
            // no other operations should be allocating buffers
            NUVO_ASSERT(0);
        }
    }
    else
    {
        NUVO_ASSERT(!"Invalid Connection state");
    }

    nuvo_mutex_unlock(&conn->sc_mutex);
}

void nuvo_pr_sconn_req_alloc_cb(struct nuvo_pr_req_alloc *alloc)
{
    struct nuvo_pr_server_conn *conn = (struct
                                        nuvo_pr_server_conn *)alloc->tag.ptr;

    nuvo_mutex_lock(&conn->sc_mutex);
    struct nuvo_io_request *req = alloc->req;

    if (conn->sc_state == NUVO_SCCS_CLOSING)
    {
        nuvo_pr_req_free(&nuvo_pr->server_req_pool, req);
        conn->recv_state = NUVO_SCRS_HEADER;

        if (conn->req_outstanding == 0)
        {
            conn->sc_state = NUVO_SCCS_CLOSED;
            nuvo_pr_sconn_free(conn);
            NUVO_LOG(pr, 0,
                     "Connection Shutdown - conn %d closed after req callback completed - Success",
                     GET_PR_SCONN_IDX(conn));
        }
    }
    else if (conn->sc_state == NUVO_SCCS_ERROR)
    {
        // The conn_mgr will transition to closing, don't do anything.
        NUVO_LOG(pr, 0,
                 "Connection Recovery - conn %d received req alloc callback for a connection that was in error state.",
                 GET_PR_SCONN_IDX(conn));

        nuvo_pr_req_free(&nuvo_pr->server_req_pool, req);
        conn->recv_state = NUVO_SCRS_HEADER;
    }
    else if (conn->sc_state == NUVO_SCCS_CLOSED)
    {
        // It is valid to get here. We release the sc_mutex, and don't
        // acutally bump req_outstanding until later (when we send to PM).
        // It does feel weird to free things after we are closed.
        // TODO: Maybe we need to have a higher level req count based on ops
        // received by the server conn, or just bump up req_outstanding earlier.
        NUVO_LOG(pr, 0,
                 "Connection Recovery - conn %d recveived alloc callback for a connection that was already closed.",
                 GET_PR_SCONN_IDX(conn));

        nuvo_pr_req_free(&nuvo_pr->server_req_pool, req);
        conn->recv_state = NUVO_SCRS_HEADER;
    }
    else if (conn->sc_state == NUVO_SCCS_CONNECTED)
    {
        req->operation = conn->recv_header.operation;
        req->tag.uint = conn->recv_header.tag.uint64;
        req->op_retry_cnt = conn->recv_header.op_retry_cnt;
        req->callback = nuvo_pr_sconn_req_comp_cb;
        req->sconn = conn;

        struct nuvo_dlist submit_list;

        switch (conn->recv_header.operation)
        {
        case NUVO_OP_READ:
        case NUVO_OP_READ_VERIFY:
        case NUVO_OP_WRITE:
            // populate IO
            conn->recv_req = req;
            req->rw.native_parcel_desc = conn->recv_header.rw.parcel_desc;
            req->rw.block_offset = conn->recv_header.rw.block_offset;
            req->rw.block_count = conn->recv_header.rw.block_count;
            req->rw.io_origin = conn->recv_header.rw.io_origin;
            // allocate buffers for read
            nuvo_pr_buf_alloc_init_req(&conn->buf_alloc,
                                       req,
                                       (union nuvo_tag)((void *)conn),
                                       nuvo_pr_sconn_buf_alloc_cb);

            conn->recv_state = NUVO_SCRS_WAIT;

            nuvo_mutex_unlock(&conn->sc_mutex);
            nuvo_pr_buf_alloc_batch(&nuvo_pr->server_buf_pool,
                                    &conn->buf_alloc);
            nuvo_mutex_lock(&conn->sc_mutex);
            break;

        case NUVO_OP_OPEN:
            // pass open to underlying layer
            uuid_copy(req->open.parcel_uuid,
                      conn->recv_header.open.parcel_uuid);
            uuid_copy(req->open.device_uuid,
                      conn->recv_header.open.device_uuid);
            uuid_copy(req->open.volume_uuid,
                      conn->recv_header.open.volume_uuid);

            nuvo_dlist_init(&submit_list);
            nuvo_dlist_insert_head(&submit_list, &req->list_node);

            conn->recv_state = NUVO_SCRS_HEADER;

            // track outstanding requests
            conn->req_outstanding++;

            nuvo_mutex_unlock(&conn->sc_mutex);
            nuvo_pm_submit(&submit_list);
            nuvo_mutex_lock(&conn->sc_mutex);

            // run process recv in case more data has come in while we waited
            nuvo_pr_sconn_process_recv(conn);
            break;

        case NUVO_OP_CLOSE:
            // pass open to underlying layer
            req->close.native_parcel_desc = conn->recv_header.close.parcel_desc;

            nuvo_dlist_init(&submit_list);
            nuvo_dlist_insert_head(&submit_list, &req->list_node);

            conn->recv_state = NUVO_SCRS_HEADER;

            // track outstanding requests
            conn->req_outstanding++;

            nuvo_mutex_unlock(&conn->sc_mutex);
            nuvo_pm_submit(&submit_list);
            nuvo_mutex_lock(&conn->sc_mutex);

            // run process recv in case more data has come in while we waited
            nuvo_pr_sconn_process_recv(conn);
            break;

        case NUVO_OP_ALLOC:
            uuid_copy(req->alloc.parcel_uuid,
                      conn->recv_header.alloc.parcel_uuid);
            uuid_copy(req->alloc.device_uuid,
                      conn->recv_header.alloc.device_uuid);
            uuid_copy(req->alloc.volume_uuid,
                      conn->recv_header.alloc.volume_uuid);
            nuvo_dlist_init(&submit_list);
            nuvo_dlist_insert_head(&submit_list, &req->list_node);

            conn->recv_state = NUVO_SCRS_HEADER;

            // track outstanding requests
            conn->req_outstanding++;

            nuvo_mutex_unlock(&conn->sc_mutex);
            nuvo_pm_submit(&submit_list);
            nuvo_mutex_lock(&conn->sc_mutex);

            // run process recv in case more data has come in while we waited
            nuvo_pr_sconn_process_recv(conn);
            break;

        case NUVO_OP_FREE:
            uuid_copy(req->free.parcel_uuid,
                      conn->recv_header.free.parcel_uuid);
            uuid_copy(req->free.device_uuid,
                      conn->recv_header.free.device_uuid);
            uuid_copy(req->free.volume_uuid,
                      conn->recv_header.free.volume_uuid);
            nuvo_dlist_init(&submit_list);
            nuvo_dlist_insert_head(&submit_list, &req->list_node);

            conn->recv_state = NUVO_SCRS_HEADER;

            // track outstanding requests
            conn->req_outstanding++;

            nuvo_mutex_unlock(&conn->sc_mutex);
            nuvo_pm_submit(&submit_list);
            nuvo_mutex_lock(&conn->sc_mutex);

            // run process recv in case more data has come in while we waited
            nuvo_pr_sconn_process_recv(conn);
            break;

        case NUVO_OP_DEV_INFO:
            uuid_copy(req->dev_info.device_uuid,
                      conn->recv_header.dev_info.device_uuid);
            nuvo_dlist_init(&submit_list);
            nuvo_dlist_insert_head(&submit_list, &req->list_node);

            conn->recv_state = NUVO_SCRS_HEADER;

            // track outstanding requests
            conn->req_outstanding++;

            nuvo_mutex_unlock(&conn->sc_mutex);
            nuvo_pm_submit(&submit_list);
            nuvo_mutex_lock(&conn->sc_mutex);

            // run process recv in case more data has come in while we waited
            nuvo_pr_sconn_process_recv(conn);
            break;

        default:
            nuvo_mutex_unlock(&conn->sc_mutex);
            NUVO_PANIC("Invalid request header operation %d.",
                       conn->recv_header.operation);
        }
    }
    else
    {
        NUVO_ASSERT(!"Invalid Connection state");
    }

    nuvo_mutex_unlock(&conn->sc_mutex);
}

nuvo_return_t nuvo_pr_sconn_process_recv(struct nuvo_pr_server_conn *conn)
{
    ssize_t ret;

    NUVO_ASSERT_MUTEX_HELD(&conn->sc_mutex);

    while (1)
    {
        // Several places call this without checking state (after releasing and
        // reacquiring the conn->sc_mutex).  So checking for state changes here.
        if (conn->sc_state != NUVO_SCCS_CONNECTED)
        {
            return (-NUVO_E_CONN_CLOSED);
        }

        if (conn->recv_state == NUVO_SCRS_WAIT)
        {
            // wait for callback to move us to next state
            break;
        }
        else if (conn->recv_state == NUVO_SCRS_HEADER)
        {
            ret = recv(conn->sock_fd,
                       (void *)((uintptr_t)&conn->recv_header + conn->recv_count),
                       sizeof(conn->recv_header) - conn->recv_count, 0);
            int64_t l_errno = errno;

            if (test_fi_inject_rc(TEST_FI_PR_SERVER_RECV_HEADER,
                                  nuvo_pr->pr_test_info, &l_errno))
            {
                ret = -1;
            }

            if (ret < 0)
            {
                if (l_errno == EAGAIN || l_errno == EWOULDBLOCK)
                {
                    // can't receive more on socket without blocking
                    // break and continue when epoll lets us know when can receive more
                }
                else if (l_errno == EINTR)
                {
                    // we were interrupted, try again
                    continue;
                }
                else
                {
                    NUVO_ERROR_PRINT(
                        "Connection Error - conn %d terminating due to recv() failure: %d",
                        GET_PR_SCONN_IDX(conn), l_errno);
                    nuvo_pr_sconn_handle_error(conn, l_errno, NUVO_CCR_RECV);
                    return (-NUVO_E_RECV);
                }
                break;
            }
            else if (ret == 0)
            {
                if (l_errno == EAGAIN)
                {
                    // During a functional test I saw a ret 0 and errno EAGAIN.
                    // So adding this to allow another retry attempt.
                    break;
                }

                // connection has been closed
                NUVO_ERROR_PRINT(
                    "Connection Error - conn %d closed in the middle of recv() request: %d",
                    GET_PR_SCONN_IDX(conn), l_errno);
                nuvo_pr_sconn_handle_error(conn, l_errno,
                                           NUVO_CCR_RECV_NO_DATA);
                return (-NUVO_E_CONN_CLOSED);
            }

            conn->recv_count += ret;
            conn->recv_total_bytes += ret;

            // if we've received the entire header, process it
            if (conn->recv_count == sizeof(conn->recv_header))
            {
                // we've received the header, now we must allocate a nuvo_io_request
                // verify header hash
                if (conn->recv_header.hash !=
                    nuvo_hash(&conn->recv_header,
                              offsetof(struct nuvo_net_req_header, hash)))
                {
                    NUVO_PANIC(
                        "Connection Error - terminating due to invalid header hash.");
                    nuvo_pr_sconn_handle_error(conn, NUVO_E_BAD_HASH,
                                               NUVO_CCR_HEADER_HASH);
                    return (-NUVO_E_BAD_HASH);
                }

                conn->recv_count = 0;
                conn->recv_state = NUVO_SCRS_WAIT;
                nuvo_dlnode_init(&conn->req_alloc.list_node);
                conn->req_alloc.callback = nuvo_pr_sconn_req_alloc_cb;
                conn->req_alloc.tag.ptr = conn;

                if (conn->recv_header.op_retry_cnt > 0)
                {
                    NUVO_LOG(pr, 0,
                             "Connection Recovery - conn %d processing a retried operation, type: %d. Op retried %d times.",
                             GET_PR_SCONN_IDX(conn),
                             conn->recv_header.operation,
                             conn->recv_header.op_retry_cnt);
                }
                nuvo_mutex_unlock(&conn->sc_mutex);

                nuvo_pr_req_alloc_cb(&nuvo_pr->server_req_pool,
                                     &conn->req_alloc);
                nuvo_mutex_lock(&conn->sc_mutex);
            }
        }
        else if (conn->recv_state == NUVO_SCRS_HASHESDATA)
        {
            // both write and read verify requests receive hashes, but only write requests receive data
            NUVO_ASSERT((conn->recv_req->operation == NUVO_OP_WRITE) ||
                        (conn->recv_req->operation == NUVO_OP_READ_VERIFY));

            // find the iovec we're in, and the offset into that iovec
            uint_fast16_t iov_index;
            uint_fast32_t offset;
            struct iovec *iovs = &conn->recv_req->rw.hashes_iovec;
            if (conn->recv_count < iovs->iov_len)
            {
                iov_index = 0;
                offset = conn->recv_count;
            }
            else
            {
                iov_index = 1 + (conn->recv_count - iovs->iov_len) /
                            NUVO_BLOCK_SIZE;
                offset = (conn->recv_count - iovs->iov_len) % NUVO_BLOCK_SIZE;
            }

            // save a copy of the original iovec
            struct iovec orig_iovec = iovs[iov_index];

            // update iovec to point to the current position in the recv stream
            iovs[iov_index].iov_base =
                (void *)((uintptr_t)iovs[iov_index].iov_base + offset);
            iovs[iov_index].iov_len -= offset;

            // recv as much as we can
            ret = readv(conn->sock_fd, &iovs[iov_index],
                        conn->recv_req->rw.block_count + 1 - iov_index);
            int64_t l_errno = errno;

            if (test_fi_inject_rc(TEST_FI_PR_SERVER_RECV_DATA,
                                  nuvo_pr->pr_test_info, &l_errno))
            {
                ret = -1;
            }

            // restore the original iovec
            iovs[iov_index] = orig_iovec;

            if (ret < 0)
            {
                if (l_errno == EAGAIN || l_errno == EWOULDBLOCK)
                {
                    // can't receive more on socket without blocking
                    // break and continue when epoll lets us know when can receive more
                }
                else if (l_errno == EINTR)
                {
                    // we were interrupted, try again
                    continue;
                }
                else
                {
                    NUVO_ERROR_PRINT(
                        "Connection Error - conn %d terminating due to readv() failure: %d",
                        GET_PR_SCONN_IDX(conn), l_errno);
                    nuvo_pr_sconn_handle_error(conn, l_errno, NUVO_CCR_READV);
                    return (-NUVO_E_RECV);
                }
                break;
            }
            else if (ret == 0)
            {
                // connection has been closed
                NUVO_ERROR_PRINT(
                    "Connection Error - conn %d closed in the middle of readv() request: %d",
                    GET_PR_SCONN_IDX(conn), l_errno);
                nuvo_pr_sconn_handle_error(conn, l_errno,
                                           NUVO_CCR_READV_NO_DATA);
                return (-NUVO_E_CONN_CLOSED);
            }

            conn->recv_count += ret;
            conn->recv_total_bytes += ret;

            // check if we're done with receiving the data
            NUVO_ASSERT(conn->recv_count <= conn->recv_req->rw.block_count *
                        NUVO_BLOCK_SIZE + iovs->iov_len);
            if (conn->recv_count == conn->recv_req->rw.block_count *
                NUVO_BLOCK_SIZE + iovs->iov_len)
            {
                struct nuvo_io_request *req = conn->recv_req;
                struct nuvo_dlist       submit_list;
                nuvo_dlist_init(&submit_list);

                // if this is a write request verify the hashes of the write buffers
                // read verify requests only verify the hashes sent after the read
                if (conn->recv_req->operation == NUVO_OP_WRITE)
                {
                    for (uint_fast32_t i = 0; i < req->rw.block_count; i++)
                    {
                        if (req->rw.block_hashes[i] != nuvo_hash(
                                req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE))
                        {
                            NUVO_PANIC(
                                "Connection terminating due to invalid data hash.");
                            nuvo_pr_sconn_handle_error(conn, NUVO_E_BAD_HASH,
                                                       NUVO_CCR_DATA_HASH);
                            return (-NUVO_E_BAD_HASH);
                        }
                    }
                }

                nuvo_dlist_insert_head(&submit_list, &req->list_node);
                conn->recv_req = NULL;

                // track outstanding requests
                conn->req_outstanding++;

                conn->recv_state = NUVO_SCRS_HEADER;
                conn->recv_count = 0;


                nuvo_mutex_unlock(&conn->sc_mutex);
                nuvo_pm_submit(&submit_list);
                nuvo_mutex_lock(&conn->sc_mutex);
            }
        }
        else
        {
            // invalid state
            NUVO_PANIC("Invalid server connection receive state %d.",
                       conn->recv_state);
        }
    }

    return (0);
}

nuvo_return_t nuvo_pr_sconn_process_send(struct nuvo_pr_server_conn *conn)
{
    ssize_t ret;

    NUVO_ASSERT_MUTEX_HELD(&conn->sc_mutex);

    if (conn->sc_state != NUVO_SCCS_CONNECTED)
    {
        return (-NUVO_E_CONN_CLOSED);
    }

    while (1)
    {
        if (conn->send_state == NUVO_SCSS_IDLE)
        {
            conn->send_req = nuvo_dlist_remove_head_object(
                &conn->req_ready_list, struct nuvo_io_request, list_node);

            if (conn->send_req != NULL)
            {
                // populate the header data here
                memset(&conn->send_header, 0, sizeof(conn->send_header));
                conn->send_header.tag.uint64 = conn->send_req->tag.uint;
                conn->send_header.status = conn->send_req->status;

                // TODO: Have a limit for max number of op retries?
                if (conn->send_req->op_retry_cnt > 0)
                {
                    NUVO_LOG(pr, 0,
                             "Connection Recovery - conn %d received server side completion for a retried operation. Op retried %d times.",
                             GET_PR_SCONN_IDX(conn),
                             conn->send_req->op_retry_cnt);
                    if (conn->send_req->op_retry_cnt >= NUVO_PR_MAX_OP_RETRIES)
                    {
                        NUVO_ASSERT(
                            !"Retried this op too many times. Giving up.");
                    }
                }

                switch (conn->send_req->operation)
                {
                case NUVO_OP_READ:
                case NUVO_OP_READ_VERIFY:
                    break;

                case NUVO_OP_WRITE:
                    break;

                case NUVO_OP_OPEN:
                    conn->send_header.open.parcel_desc =
                        conn->send_req->open.parcel_desc;
                    break;

                case NUVO_OP_CLOSE:
                    break;

                case NUVO_OP_ALLOC:
                    uuid_copy(conn->send_header.alloc.parcel_uuid,
                              conn->send_req->alloc.parcel_uuid);
                    break;

                case NUVO_OP_FREE:
                    break;

                case NUVO_OP_DEV_INFO:
                    conn->send_header.dev_info.device_size =
                        conn->send_req->dev_info.device_size;
                    conn->send_header.dev_info.parcel_size =
                        conn->send_req->dev_info.parcel_size;
                    break;

                default:
                    NUVO_PANIC("Invalid request operation %d.",
                               conn->send_req->operation);
                }

                // Fault injection testing for idempotent ops.
                if (nuvo_pr_fi_idempotent_error(conn->send_req))
                {
                    NUVO_ERROR_PRINT(
                        "Connection Error - conn %d terminating due to idempotent error trigger on op type %d during server side response.",
                        GET_PR_SCONN_IDX(conn),
                        conn->send_req->operation);
                    nuvo_pr_sconn_handle_error(conn, -NUVO_E_SEND,
                                               NUVO_CCR_SEND);
                    return (-NUVO_E_SEND);
                }

                // generate hash for filled header
                conn->send_header.hash = nuvo_hash(&conn->send_header,
                                                   offsetof(struct nuvo_net_resp_header,
                                                            hash));

                conn->send_count = 0;
                conn->send_state = NUVO_CCSS_HEADER;
            }
            else
            {
                // nothing to send, exit function
                break;
            }
        }
        else if (conn->send_state == NUVO_SCSS_HEADER)
        {
            ssize_t ret = send(conn->sock_fd,
                               (void *)((uintptr_t)&conn->send_header + conn->send_count),
                               sizeof(conn->send_header) - conn->send_count, 0);
            int64_t l_errno = errno;

            if (test_fi_inject_rc(TEST_FI_PR_SERVER_SEND_HEADER,
                                  nuvo_pr->pr_test_info, &l_errno))
            {
                ret = -1;
            }

            if (ret < 0)
            {
                if (l_errno == EINTR)
                {
                    // we were interrupted, try again
                    continue;
                }
                NUVO_ERROR_PRINT(
                    "Connection Error - conn %d terminating due to send() failure: %d",
                    GET_PR_SCONN_IDX(conn), l_errno);
                nuvo_pr_sconn_handle_error(conn, l_errno, NUVO_CCR_SEND);
                return (-NUVO_E_SEND);
            }
            else if (ret == 0)
            {
                NUVO_ASSERT(l_errno == EAGAIN || l_errno == EWOULDBLOCK);
                // can't send more on socket without blocking
                // break and continue when epoll lets us know we can send more
                break;
            }

            conn->send_count += ret;
            conn->send_total_bytes += ret;

            // check if we're done with sending the header
            NUVO_ASSERT(conn->send_count <= sizeof(conn->send_header));
            if (conn->send_count == sizeof(conn->send_header))
            {
                conn->send_count = 0;
                // finished sending the header, move onto data if there is any
                if ((conn->send_req->operation == NUVO_OP_READ) ||
                    (conn->send_req->operation == NUVO_OP_READ_VERIFY))
                {
                    // read is only operation that sends data currently
                    // but first we need to send hashes
                    conn->send_state = NUVO_SCSS_HASHESDATA;
                    conn->send_req->rw.hashes_iovec.iov_base =
                        conn->send_req->rw.block_hashes;
                    conn->send_req->rw.hashes_iovec.iov_len =
                        NUVO_HASH_BYTES * conn->send_req->rw.block_count;
                }
                else
                {
                    // we've sent request completion, so we're done
                    // free req and clean up
                    if (conn->send_req->operation == NUVO_OP_WRITE)
                    {
                        nuvo_pr_buf_free_req(&nuvo_pr->server_buf_pool,
                                             conn->send_req);
                    }
                    nuvo_pr_req_free(&nuvo_pr->server_req_pool, conn->send_req);
                    conn->send_req = NULL;

                    conn->send_state = NUVO_CCSS_IDLE;
                }
            }
        }
        else if (conn->send_state == NUVO_SCSS_HASHESDATA)
        {
            NUVO_ASSERT((conn->send_req->operation == NUVO_OP_READ) ||
                        (conn->send_req->operation == NUVO_OP_READ_VERIFY))

            // find the iovec we're in, and the offset into that iovec
            uint_fast16_t iov_index;
            uint_fast32_t offset;
            struct iovec *iovs = &conn->send_req->rw.hashes_iovec;
            if (conn->send_count < iovs->iov_len)
            {
                iov_index = 0;
                offset = conn->send_count;
            }
            else
            {
                iov_index = 1 + (conn->send_count - iovs->iov_len) /
                            NUVO_BLOCK_SIZE;
                offset = (conn->send_count - iovs->iov_len) % NUVO_BLOCK_SIZE;
            }

            // save a copy of the original iovec
            struct iovec orig_iovec = iovs[iov_index];

            // update iovec to point to the current position in the recv stream
            iovs[iov_index].iov_base =
                (void *)((uintptr_t)iovs[iov_index].iov_base + offset);
            iovs[iov_index].iov_len -= offset;

            // send as much as we can
            ret = writev(conn->sock_fd, &iovs[iov_index],
                         conn->send_req->rw.block_count + 1 - iov_index);
            int64_t l_errno = errno;

            if (test_fi_inject_rc(TEST_FI_PR_SERVER_SEND_DATA,
                                  nuvo_pr->pr_test_info, &l_errno))
            {
                ret = -1;
            }

            // restore the original iovec
            iovs[iov_index] = orig_iovec;

            // check for errors
            if (ret < 0)
            {
                if (l_errno == EINTR)
                {
                    // we were interrupted, try again
                    continue;
                }
                else if (l_errno == EAGAIN || l_errno == EWOULDBLOCK)
                {
                    // can't send more on socket without blocking
                    // break and continue when epoll lets us know when can send more
                    break;
                }
                NUVO_ERROR_PRINT(
                    "Connection Error - conn %d terminating due to writev() failure: %d",
                    GET_PR_SCONN_IDX(conn), l_errno);
                nuvo_pr_sconn_handle_error(conn, l_errno, NUVO_CCR_WRITEV);
                return (-NUVO_E_SEND);
            }
            else if (ret == 0)
            {
                NUVO_ASSERT(l_errno == EAGAIN || l_errno == EWOULDBLOCK);
                // can't send more on socket without blocking
                // break and continue when epoll lets us know when can send more
                break;
            }

            conn->send_count += ret;
            conn->send_total_bytes += ret;

            // check if we're done with sending the data
            NUVO_ASSERT(conn->send_count <= conn->send_req->rw.block_count *
                        NUVO_BLOCK_SIZE + iovs->iov_len);
            if (conn->send_count == conn->send_req->rw.block_count *
                NUVO_BLOCK_SIZE + iovs->iov_len)
            {
                // finished sending data, so this request is complete
                nuvo_pr_buf_free_req(&nuvo_pr->server_buf_pool, conn->send_req);
                nuvo_pr_req_free(&nuvo_pr->server_req_pool, conn->send_req);

                conn->send_count = 0;
                conn->send_req = NULL;

                conn->send_state = NUVO_SCSS_IDLE;
            }
        }
    }
    return (0);
}

void nuvo_pr_sconn_handle_error(struct nuvo_pr_server_conn *conn,
                                int64_t                     close_err,
                                enum nuvo_conn_close_reason close_reason)
{
    NUVO_ASSERT_MUTEX_HELD(&conn->sc_mutex);

    NUVO_LOG(pr, 0, "Connection Error - conn %d encountered error in state: %d",
             GET_PR_SCONN_IDX(conn), conn->sc_state);

    switch (conn->sc_state)
    {
    case NUVO_SCCS_CLOSED:
        NUVO_DEBUG_ASSERT(false,
                          "Printing stack trace when server side receives error while connection is closed.");
        return;

    case NUVO_SCCS_CONNECTED:
        // First error detected, trigger recovery
        NUVO_LOG(pr, 0,
                 "Connection Error - conn %d, notifying connection manager thread.",
                 GET_PR_SCONN_IDX(conn));

        // Changing state to error so conn_mgr knows which conn to recover
        conn->sc_state = NUVO_SCCS_ERROR;
        conn->prev_close_reason = close_reason;
        conn->prev_close_err = close_err;

        // Send signal to the conn_mgr thread to do some work
        nuvo_mutex_lock(&nuvo_pr->cm_info.cm_work_mutex);
        nuvo_pr->cm_info.conn_recovery_cnt++;
        nuvo_cond_signal(&nuvo_pr->cm_info.cm_work_cv);
        nuvo_mutex_unlock(&nuvo_pr->cm_info.cm_work_mutex);
        break;

    case NUVO_SCCS_CLOSING:
    case NUVO_SCCS_ERROR:
        // The connection is already in the process of closing,
        // more notifications are not required.
        break;
    }
}

void nuvo_pr_sconn_shutdown(struct nuvo_pr_server_conn *conn,
                            int64_t                     close_err,
                            enum nuvo_conn_close_reason close_reason)
{
    struct epoll_event event;

    NUVO_ASSERT_MUTEX_HELD(&conn->sc_mutex);

    // We could be calling a second time if there were requests in flight
    // the first time through.
    if (conn->sc_state == NUVO_SCCS_CLOSING)
    {
        if (conn->req_outstanding == 0 && conn->recv_req == NULL)
        {
            conn->sc_state = NUVO_SCCS_CLOSED;
            nuvo_pr_sconn_free(conn);
            NUVO_LOG(pr, 0,
                     "Connection Shutdown - conn %d (server side) pending requests completed - Success",
                     GET_PR_SCONN_IDX(conn));
        }
        else
        {
            uint_fast64_t now = nuvo_get_timestamp();

            NUVO_LOG_CAN_SUPPRESS(pr, 0, SUP_GRP_PR_SHUTDOWN_PENDING, 1,
                                  "Connection Shutdown - conn %d (server side) still has %d pending requests in flight.",
                                  GET_PR_SCONN_IDX(conn),
                                  conn->req_outstanding);

            if ((now - conn->shutdown_start_ts) >
                (NUVO_PR_CONN_SHUTDOWN_MAX_SECS * 1000000000ull))
            {
                NUVO_LOG(pr, 0,
                         "Connection Shutdown - conn %d (server side) shutdown not complete after %d seconds, giving up.",
                         GET_PR_SCONN_IDX(conn),
                         NUVO_PR_CONN_SHUTDOWN_MAX_SECS);
                NUVO_ASSERT(!"Connection Shutdown unable to make progress after several minutes.");
            }
        }

        return;
    }

    conn->shutdown_start_ts = nuvo_get_timestamp();

    // remove socket from epoll
    epoll_ctl(nuvo_pr->server_epoll_fd, EPOLL_CTL_DEL, conn->sock_fd, &event);
    // close socket
    close(conn->sock_fd);

    // change state to closing
    conn->sc_state = NUVO_SCCS_CLOSING;

    conn->prev_close_err = close_err;
    conn->prev_close_reason = close_reason;

    // depending on state, handle freeing of recv_req
    if (conn->recv_state == NUVO_SCRS_WAIT)
    {
        // we're waiting on a callback for allocating a req or buffers
        // defer freeing recv_req until callback
    }
    else
    {
        // recv was in process of receiving, just free everything
        conn->recv_state = NUVO_SCRS_HEADER;
        if (conn->recv_req != NULL)
        {
            // reads and writes have buffers too
            if (conn->recv_req->operation == NUVO_OP_READ ||
                conn->recv_req->operation == NUVO_OP_READ_VERIFY ||
                conn->recv_req->operation == NUVO_OP_WRITE)
            {
                nuvo_pr_buf_free_req(&nuvo_pr->server_buf_pool, conn->recv_req);
            }
            nuvo_pr_req_free(&nuvo_pr->server_req_pool, conn->recv_req);
            conn->recv_req = NULL;
        }
    }

    conn->recv_count = 0;
    conn->recv_total_bytes = 0;
    conn->send_state = NUVO_SCSS_IDLE;
    conn->send_count = 0;
    conn->send_total_bytes = 0;

    // drop send reqs, and any pending reqs
    if (conn->send_req != NULL)
    {
        if (conn->send_req->operation == NUVO_OP_READ ||
            conn->send_req->operation == NUVO_OP_READ_VERIFY ||
            conn->send_req->operation == NUVO_OP_WRITE)
        {
            nuvo_pr_buf_free_req(&nuvo_pr->server_buf_pool, conn->send_req);
        }
        nuvo_pr_req_free(&nuvo_pr->server_req_pool, conn->send_req);
        conn->send_req = NULL;
    }
    struct nuvo_io_request *req;
    while ((req = nuvo_dlist_remove_head_object(&conn->req_ready_list, struct
                                                nuvo_io_request, list_node)) != NULL)
    {
        if (req->operation == NUVO_OP_READ ||
            req->operation == NUVO_OP_READ_VERIFY ||
            req->operation == NUVO_OP_WRITE)
        {
            nuvo_pr_buf_free_req(&nuvo_pr->server_buf_pool, req);
        }
        nuvo_pr_req_free(&nuvo_pr->server_req_pool, req);
    }

    // check if all outstanding requests are complete, and we don't have deferred recv_req
    if (conn->req_outstanding == 0 && conn->recv_req == NULL)
    {
        conn->sc_state = NUVO_SCCS_CLOSED;
        nuvo_pr_sconn_free(conn);
        NUVO_LOG(pr, 0, "Connection Shutdown - conn %d - Success.",
                 GET_PR_SCONN_IDX(conn));
    }
    else
    {
        NUVO_LOG(pr, 0,
                 "Connection Shutdown - conn %d - Pending.  Waiting for outstanding requests.",
                 GET_PR_SCONN_IDX(conn));
    }
}

nuvo_return_t nuvo_pr_req_pool_init(struct nuvo_pr_req_pool *req_pool)
{
    int ret;

    req_pool->req_max_used = 0;
    req_pool->req_free_cnt = NUVO_ARRAY_LENGTH(req_pool->req_table);
    nuvo_dlist_init(&req_pool->req_free_list);
    nuvo_dlist_init(&req_pool->req_alloc_list);

    ret = nuvo_mutex_init(&req_pool->req_mutex);
    if (ret != 0)
    {
        ret = -NUVO_ENOMEM;
        return (ret);
    }

    return (0);
}

void nuvo_pr_req_pool_destroy(struct nuvo_pr_req_pool *req_pool)
{
    nuvo_mutex_destroy(&req_pool->req_mutex);
}

struct nuvo_io_request *nuvo_pr_req_alloc(struct nuvo_pr_req_pool *req_pool)
{
    nuvo_mutex_lock(&req_pool->req_mutex);

    struct nuvo_io_request *req = nuvo_dlist_remove_head_object(
        &req_pool->req_free_list, struct nuvo_io_request, list_node);

    if (req == NULL)
    {
        if (req_pool->req_max_used < NUVO_ARRAY_LENGTH(req_pool->req_table))
        {
            req = &req_pool->req_table[req_pool->req_max_used++];
            nuvo_dlnode_init(&req->list_node);
        }
    }

    if (req != NULL)
    {
        req_pool->req_free_cnt--;
    }

    nuvo_mutex_unlock(&req_pool->req_mutex);

    // This will not print unless pr log level is set to a high value
    nuvo_pr_print_req_buf_stats();

    return (req);
}

void nuvo_pr_req_alloc_cb(struct nuvo_pr_req_pool *req_pool, struct
                          nuvo_pr_req_alloc *alloc)
{
    nuvo_mutex_lock(&req_pool->req_mutex);

    int do_callback = 0;

    // try to alloc, otherwise enqueue request
    alloc->req = nuvo_dlist_remove_head_object(&req_pool->req_free_list, struct
                                               nuvo_io_request, list_node);
    if (alloc->req != NULL)
    {
        req_pool->req_free_cnt--;
        // great, invoke the callback
        do_callback = 1;
    }
    else
    {
        // can we pull more from our table?
        if (req_pool->req_max_used < NUVO_ARRAY_LENGTH(req_pool->req_table))
        {
            // great, invoke the callback
            alloc->req = &req_pool->req_table[req_pool->req_max_used++];
            nuvo_dlnode_init(&alloc->req->list_node);
            req_pool->req_free_cnt--;
            do_callback = 1;
        }
        else
        {
            // enqueue this allocation request on to the waiting queue
            nuvo_dlist_insert_tail(&req_pool->req_alloc_list,
                                   &alloc->list_node);
        }
    }
    nuvo_mutex_unlock(&req_pool->req_mutex);

    // This will not print unless pr log level is set to a high value
    nuvo_pr_print_req_buf_stats();

    if (do_callback != 0)
    {
        alloc->callback(alloc);
    }
}

void nuvo_pr_req_free(struct nuvo_pr_req_pool *req_pool, struct
                      nuvo_io_request *req)
{
    NUVO_ASSERT(req - req_pool->req_table >= 0);
    NUVO_ASSERT(req - req_pool->req_table <
                (intptr_t)NUVO_ARRAY_LENGTH(req_pool->req_table));

    struct nuvo_pr_req_alloc *alloc;
    nuvo_mutex_lock(&req_pool->req_mutex);

    alloc = nuvo_dlist_remove_head_object(&req_pool->req_alloc_list, struct
                                          nuvo_pr_req_alloc, list_node);
    if (alloc == NULL)
    {
        req_pool->req_free_cnt++;
        nuvo_dlist_insert_head(&req_pool->req_free_list, &req->list_node);
    }
    else
    {
        alloc->req = req;
    }

    nuvo_mutex_unlock(&req_pool->req_mutex);

    if (alloc != NULL)
    {
        // we had a queue allocation request, complete it
        alloc->callback(alloc);
    }
}

_Atomic struct nuvo_pr_pdef *nuvo_pr_pdef_alloc()
{
    nuvo_mutex_lock(&nuvo_pr->pdef_mutex);
    uint_fast32_t index = nuvo_pr->pdef_free_list;
    _Atomic struct  nuvo_pr_pdef *pdef = NULL;
    struct nuvo_pr_pdef           pdef_val;
    // check free list for pdefs
    if (index != NUVO_PR_INVALID32)
    {
        pdef = &nuvo_pr->pdef_table[nuvo_pr->pdef_free_list];

        pdef_val = atomic_load(pdef);
        nuvo_pr->pdef_free_list = pdef_val.next_pdef_index;
        pdef_val.node_index = NUVO_PR_NODE_INVALID;
        pdef_val.outstanding_io = 0;
        pdef_val.native_pd = -1;
        atomic_store(pdef, pdef_val);
    }
    else
    {
        // use next pdef in table if none on free list
        if (nuvo_pr->pdef_used < NUVO_ARRAY_LENGTH(nuvo_pr->pdef_table))
        {
            pdef = &nuvo_pr->pdef_table[nuvo_pr->pdef_used++];
            pdef_val = atomic_load(pdef);
            pdef_val.node_index = NUVO_PR_NODE_INVALID;
            pdef_val.gen = 0;
            pdef_val.outstanding_io = 0;
            pdef_val.native_pd = -1;
            atomic_store(pdef, pdef_val);
        }
    }
    nuvo_mutex_unlock(&nuvo_pr->pdef_mutex);

    return (pdef);
}

struct nuvo_io_request *nuvo_pr_client_req_alloc()
{
    return (nuvo_pr_req_alloc(&nuvo_pr->client_req_pool));
}

void nuvo_pr_client_req_alloc_cb(struct nuvo_pr_req_alloc *alloc)
{
    return (nuvo_pr_req_alloc_cb(&nuvo_pr->client_req_pool, alloc));
}

void nuvo_pr_client_req_free(struct nuvo_io_request *req)
{
    nuvo_pr_req_free(&nuvo_pr->client_req_pool, req);
}

void nuvo_pr_pdef_free(_Atomic struct nuvo_pr_pdef *pdef)
{
    // just put the pdef on the free list
    NUVO_ASSERT(pdef - nuvo_pr->pdef_table >= 0);
    NUVO_ASSERT(pdef - nuvo_pr->pdef_table <
                (intptr_t)NUVO_ARRAY_LENGTH(nuvo_pr->pdef_table));

    uint_fast32_t pdef_index = pdef - nuvo_pr->pdef_table;

    struct nuvo_pr_pdef pdef_val = atomic_load(pdef);

    // increment the gen to invalidate previous pd's point to this pdef
    pdef_val.gen++;
    pdef_val.node_index = NUVO_PR_NODE_INVALID;
    nuvo_mutex_lock(&nuvo_pr->pdef_mutex);
    pdef_val.next_pdef_index = nuvo_pr->pdef_free_list;
    atomic_store(pdef, pdef_val);
    nuvo_pr->pdef_free_list = pdef_index;
    nuvo_mutex_unlock(&nuvo_pr->pdef_mutex);
}

void nuvo_pr_pdef_remove_all(struct nuvo_pr_node_desc *node_desc)
{
    uint_fast32_t       node_index = node_desc - nuvo_pr->node_table;
    struct nuvo_pr_pdef pdef_orig, pdef_new;

    nuvo_mutex_lock(&nuvo_pr->pdef_mutex);
    for (_Atomic struct nuvo_pr_pdef *cur = nuvo_pr->pdef_table,
         *end = &nuvo_pr->pdef_table[nuvo_pr->pdef_used];
         cur < end;
         cur++)
    {
        while (1)
        {
            pdef_orig = atomic_load(cur);
            if (pdef_orig.node_index == node_index)
            {
                // found matching pdef, attempt to free it
                pdef_new = pdef_orig;
                pdef_new.gen++;
                pdef_new.next_pdef_index = nuvo_pr->pdef_free_list;
                pdef_new.node_index = NUVO_PR_NODE_INVALID;
                if (atomic_compare_exchange_weak(cur, &pdef_orig, pdef_new))
                {
                    // successfully updated pdef
                    nuvo_pr->pdef_free_list = cur - nuvo_pr->pdef_table;
                    break;
                }
            }
            else
            {
                // move onto the next pdef
                break;
            }
        }
    }

    nuvo_mutex_unlock(&nuvo_pr->pdef_mutex);
}

union parcel_descriptor nuvo_pr_pdef_to_pdesc(_Atomic struct nuvo_pr_pdef *pdef)
{
    union parcel_descriptor pdesc;
    struct nuvo_pr_pdef     pdef_val = atomic_load(pdef);

    pdesc.index = pdef - nuvo_pr->pdef_table;
    pdesc.gen = pdef_val.gen;

    return (pdesc);
}

nuvo_return_t nuvo_pr_pdef_get(union parcel_descriptor pdesc,
                               struct nuvo_pr_pdef    *pdef)
{
    nuvo_return_t ret = 0;

    NUVO_ASSERT(pdesc.index < NUVO_ARRAY_LENGTH(nuvo_pr->pdef_table));
    *pdef = atomic_load(&nuvo_pr->pdef_table[pdesc.index]);
    // check that parcel descriptor is valid
    if (pdef->gen != pdesc.gen)
    {
        // bogus parcel descriptor, reject with error status
        ret = -NUVO_EINVAL;
    }

    return (ret);
}

nuvo_return_t nuvo_pr_pdef_add_outstanding(union parcel_descriptor pdesc,
                                           int_fast32_t            val)
{
    nuvo_return_t ret = 0;

    NUVO_ASSERT(pdesc.index < NUVO_ARRAY_LENGTH(nuvo_pr->pdef_table));
    struct nuvo_pr_pdef pdef_orig, pdef_new;

    while (1)
    {
        pdef_orig = atomic_load(&nuvo_pr->pdef_table[pdesc.index]);
        pdef_new = pdef_orig;
        // check that parcel descriptor is valid
        if (pdef_orig.gen != pdesc.gen)
        {
            // bogus parcel descriptor, reject with error status
            ret = -NUVO_EINVAL;
            break;
        }

        // Check unsigned value for decrement less than 0
        if (val < 0)
        {
            NUVO_ASSERT(pdef_new.outstanding_io >= -val);
        }


        // add operation to outstanding for pdef
        pdef_new.outstanding_io += val;

        if (atomic_compare_exchange_weak(&nuvo_pr->pdef_table[pdesc.index],
                                         &pdef_orig, pdef_new))
        {
            // succeeded, break out
            ret = 0;
            break;
        }
    }

    return (ret);
}

nuvo_return_t nuvo_pr_buf_pool_init(struct nuvo_pr_buf_pool *buf_pool)
{
    int ret;

    buf_pool->buf_max_used = 0;
    buf_pool->buf_free_cnt = NUVO_ARRAY_LENGTH(buf_pool->buf_table);
    nuvo_dlist_init(&buf_pool->buf_free_list);
    nuvo_dlist_init(&buf_pool->buf_alloc_list);

    ret = nuvo_mutex_init(&buf_pool->buf_mutex);
    if (ret != 0)
    {
        ret = -NUVO_ENOMEM;
        return (ret);
    }

    return (0);
}

void nuvo_pr_buf_pool_destroy(struct nuvo_pr_buf_pool *buf_pool)
{
    nuvo_mutex_destroy(&buf_pool->buf_mutex);
}

void *nuvo_pr_buf_get(struct nuvo_pr_buf_pool *buf_pool)
{
    void *buf = nuvo_dlist_remove_head(&buf_pool->buf_free_list);

    if (buf == NULL)
    {
        NUVO_ASSERT(buf_pool->buf_max_used <
                    NUVO_ARRAY_LENGTH(buf_pool->buf_table));
        buf = &buf_pool->buf_table[buf_pool->buf_max_used++].list_node;
    }
    buf_pool->buf_free_cnt--;

    return (buf);
}

void nuvo_pr_buf_check_allocs(struct nuvo_pr_buf_pool *buf_pool,
                              struct nuvo_dlist       *list)
{
    // it would be nice if we could make sure we held the buf lock here
    struct nuvo_pr_buf_alloc *alloc;

    while ((alloc = nuvo_dlist_get_head_object(&buf_pool->buf_alloc_list,
                                               struct nuvo_pr_buf_alloc,
                                               list_node)))
    {
        if (alloc->buf_count == 0)
        {
            struct nuvo_io_request *req = alloc->req;
            if (req->rw.block_count <= buf_pool->buf_free_cnt)
            {
                nuvo_dlist_remove(&alloc->list_node);
                for (struct iovec *cur = &req->rw.iovecs[0],
                     *end = &req->rw.iovecs[req->rw.block_count];
                     cur < end;
                     cur++)
                {
                    cur->iov_base = nuvo_pr_buf_get(buf_pool);
                    cur->iov_len = NUVO_BLOCK_SIZE;
                }
                nuvo_dlist_insert_tail(list, &alloc->list_node);
            }
            else
            {
                break;
            }
        }
        else
        {
            if (alloc->buf_count <= buf_pool->buf_free_cnt)
            {
                nuvo_dlist_remove(&alloc->list_node);
                for (void **cur = alloc->buf_list,
                     **end = &alloc->buf_list[alloc->buf_count];
                     cur < end;
                     cur++)
                {
                    *cur = nuvo_pr_buf_get(buf_pool);
                }
                nuvo_dlist_insert_tail(list, &alloc->list_node);
            }
            else
            {
                break;
            }
        }
    }
}

void *nuvo_pr_buf_alloc(struct nuvo_pr_buf_pool *buf_pool)
{
    struct nuvo_dlnode *buf = NULL;

    nuvo_mutex_lock(&buf_pool->buf_mutex);

    if (buf_pool->buf_free_cnt > 0 &&
        nuvo_dlist_get_head(&buf_pool->buf_alloc_list) == NULL)
    {
        buf = nuvo_pr_buf_get(buf_pool);
    }

    nuvo_mutex_unlock(&buf_pool->buf_mutex);

    return ((void *)buf);
}

static inline void nuvo_pr_buf_do_cbs(struct nuvo_dlist *list)
{
    struct nuvo_pr_buf_alloc *alloc;

    while ((alloc = nuvo_dlist_remove_head_object(list,
                                                  struct nuvo_pr_buf_alloc,
                                                  list_node)) != NULL)
    {
        alloc->callback(alloc);
    }
}

void nuvo_pr_buf_alloc_batch(struct nuvo_pr_buf_pool  *buf_pool,
                             struct nuvo_pr_buf_alloc *alloc)
{
    struct nuvo_dlist comp_list;

    nuvo_dlist_init(&comp_list);

    nuvo_mutex_lock(&buf_pool->buf_mutex);

    nuvo_dlist_insert_tail(&buf_pool->buf_alloc_list, &alloc->list_node);
    nuvo_pr_buf_check_allocs(buf_pool, &comp_list);

    nuvo_mutex_unlock(&buf_pool->buf_mutex);

    nuvo_pr_buf_do_cbs(&comp_list);
}

void nuvo_pr_buf_free(struct nuvo_pr_buf_pool *buf_pool, void *buf)
{
    NUVO_ASSERT(buf - (void *)&buf_pool->buf_table >= 0);
    NUVO_ASSERT(buf <= (void *)&buf_pool->buf_table[NUVO_ARRAY_LENGTH(
                                                        buf_pool->buf_table) - 1]);
    struct nuvo_dlist comp_list;
    nuvo_dlist_init(&comp_list);
    struct nuvo_dlnode *node = (struct nuvo_dlnode *)buf;

    nuvo_mutex_lock(&buf_pool->buf_mutex);

    nuvo_dlnode_init(node);
    nuvo_dlist_insert_head(&buf_pool->buf_free_list, node);
    buf_pool->buf_free_cnt++;

    // check for waiting allocation requests
    nuvo_pr_buf_check_allocs(buf_pool, &comp_list);

    nuvo_mutex_unlock(&buf_pool->buf_mutex);

    nuvo_pr_buf_do_cbs(&comp_list);
}

void nuvo_pr_buf_free_req(struct nuvo_pr_buf_pool *buf_pool,
                          struct nuvo_io_request  *req)
{
    struct nuvo_dlist comp_list;

    nuvo_dlist_init(&comp_list);
    nuvo_mutex_lock(&buf_pool->buf_mutex);

    for (struct iovec *cur = &req->rw.iovecs[0],
         *end = &req->rw.iovecs[req->rw.block_count];
         cur < end;
         cur++)
    {
        struct nuvo_dlnode *buf = (struct nuvo_dlnode *)cur->iov_base;
        nuvo_dlnode_init(buf);
        nuvo_dlist_insert_head(&buf_pool->buf_free_list, buf);
        buf_pool->buf_free_cnt++;
        cur->iov_base = NULL;
    }
    nuvo_pr_buf_check_allocs(buf_pool, &comp_list);

    nuvo_mutex_unlock(&buf_pool->buf_mutex);

    nuvo_pr_buf_do_cbs(&comp_list);
}

void nuvo_pr_buf_free_list(struct nuvo_pr_buf_pool *buf_pool, void **buf_list,
                           uint_fast32_t count)
{
    struct nuvo_dlist comp_list;

    nuvo_dlist_init(&comp_list);
    nuvo_mutex_lock(&buf_pool->buf_mutex);

    for (uint_fast32_t i = 0; i < count; i++)
    {
        struct nuvo_dlnode *buf = (struct nuvo_dlnode *)buf_list[i];
        nuvo_dlnode_init(buf);
        nuvo_dlist_insert_head(&buf_pool->buf_free_list, buf);
        buf_pool->buf_free_cnt++;
        buf_list[i] = NULL;
    }
    nuvo_pr_buf_check_allocs(buf_pool, &comp_list);

    nuvo_mutex_unlock(&buf_pool->buf_mutex);

    nuvo_pr_buf_do_cbs(&comp_list);
}

void *nuvo_pr_client_buf_alloc()
{
    return (nuvo_pr_buf_alloc(&nuvo_pr->client_buf_pool));
}

extern inline void nuvo_pr_buf_alloc_init_req(struct nuvo_pr_buf_alloc *alloc,
                                              struct nuvo_io_request   *req,
                                              union nuvo_tag            tag,
                                              void (*callback)(struct nuvo_pr_buf_alloc *));

extern inline void nuvo_pr_buf_alloc_init_list(struct nuvo_pr_buf_alloc *alloc,
                                               void                    **list,
                                               uint_fast32_t             count,
                                               union nuvo_tag            tag,
                                               void (*callback)(struct nuvo_pr_buf_alloc *));

void nuvo_pr_client_buf_alloc_batch(struct nuvo_pr_buf_alloc *alloc)
{
    nuvo_pr_buf_alloc_batch(&nuvo_pr->client_buf_pool, alloc);
}

void nuvo_pr_client_buf_free(void *buf)
{
    nuvo_pr_buf_free(&nuvo_pr->client_buf_pool, buf);
}

void nuvo_pr_client_buf_free_req(struct nuvo_io_request *req)
{
    nuvo_pr_buf_free_req(&nuvo_pr->client_buf_pool, req);
}

void nuvo_pr_client_buf_free_list(void **buf_list, uint_fast32_t count)
{
    nuvo_pr_buf_free_list(&nuvo_pr->client_buf_pool, buf_list, count);
}

nuvo_return_t nuvo_pr_get_conn(struct nuvo_pr_node_desc    *node,
                               struct nuvo_pr_client_conn **conn,
                               bool                         open_conn)
{
    nuvo_return_t ret = -NUVO_ENOTCONN;

    if (node->conn != NULL)
    {
        // check for deferred connection closure
        nuvo_mutex_lock(&node->conn->cc_mutex);
        if (node->conn->cc_state == NUVO_CCCS_CLOSED)
        {
            nuvo_pr_cconn_free(node->conn);
            nuvo_mutex_unlock(&node->conn->cc_mutex);
            node->conn = NULL;

            // remove existing pdefs
            nuvo_pr_pdef_remove_all(node);
        }
        else
        {
            ret = 0;
            *conn = node->conn;
        }
    }

    if (node->conn == NULL && open_conn == true)
    {
        // we don't have a connection to this node yet, allocate one
        *conn = nuvo_pr_cconn_alloc();
        if (*conn == NULL)
        {
            // failed to allocate a connection
            return (-NUVO_ENOMEM);
        }

        nuvo_mutex_lock(&(*conn)->cc_mutex);
        ret = nuvo_pr_cconn_open(*conn, node);
        if (ret < 0)
        {
            nuvo_pr_cconn_free(*conn);
            nuvo_mutex_unlock(&(*conn)->cc_mutex);

            return (-NUVO_E_CONNECT);
        }

        ret = 0;
        node->conn = *conn;
    }

    return (ret);
}

void nuvo_pr_submit(struct nuvo_dlist *submit_list)
{
    struct nuvo_dlist local_list, completed_list;

    nuvo_dlist_init(&local_list);
    nuvo_dlist_init(&completed_list);

    uint32_t node_index;
    struct nuvo_io_request      *req;
    union parcel_descriptor      pdesc;
    _Atomic struct nuvo_pr_pdef *pdef;
    struct nuvo_pr_pdef          pdef_val;
    struct nuvo_pr_node_desc    *node;
    struct nuvo_pr_client_conn  *conn = NULL;

    nuvo_return_t ret;
    uint_fast32_t dev_index;

    while ((req = nuvo_dlist_remove_head_object(submit_list,
                                                struct nuvo_io_request,
                                                list_node)) != NULL)
    {
        // make sure local reqs have sconn clear
        req->sconn = NULL;
        req->op_retry_cnt = 0;
        req->idempotent_status_flag = 0;

        switch (req->operation)
        {
        case NUVO_OP_READ:
        case NUVO_OP_READ_VERIFY:
        case NUVO_OP_WRITE:
            // determine if it is local or remote
            pdesc.pd = req->rw.parcel_desc;

            ret = nuvo_pr_pdef_get(pdesc, &pdef_val);

            test_fi_inject_rc(TEST_FI_PR_PDEF_GET, nuvo_pr->pr_test_info, &ret);

            if (ret < 0)
            {
                NUVO_ERROR_PRINT(
                    "Generation count mismatch, request gen count: %d, expected gen count: %d",
                    pdesc.gen, pdef_val.gen);
                // bogus parcel descriptor, reject with error status
                req->status = -1;
                req->callback(req);
                break;
            }

            ret = nuvo_pr_pdef_add_outstanding(pdesc, 1);
            if (ret < 0)
            {
                // bogus parcel descriptor, reject with error status
                req->status = -1;
                req->callback(req);
                break;
            }

            // parcel descriptor checks out, is it local?
            // save local parcel descriptor
            req->rw.native_parcel_desc = pdef_val.native_pd;
            node_index = pdef_val.node_index;
            if (node_index == NUVO_PR_LOCAL_NODE_INDEX)
            {
                // put on local rw list
                nuvo_dlist_insert_tail(&local_list, &req->list_node);
            }
            else
            {
                node = &nuvo_pr->node_table[node_index];
                nuvo_mutex_lock(&node->nd_mutex);
                ret = nuvo_pr_get_conn(node, &conn, false);
                nuvo_mutex_unlock(&node->nd_mutex);

                if (ret < 0)
                {
                    // TODO: error codes
                    nuvo_pr_pdef_add_outstanding(pdesc, -1);
                    req->status = -1;
                    req->callback(req);
                    break;
                }

                ret = nuvo_pr_cconn_enqueue_req(conn, req, &completed_list);
                nuvo_mutex_unlock(&conn->cc_mutex);
                if (ret < 0)
                {
                    nuvo_pr_pdef_add_outstanding(pdesc, -1);
                    req->status = ret;
                    req->callback(req);
                    break;
                }
            }

            break;

        case NUVO_OP_OPEN:
            // determine if it is local or remote

            nuvo_mutex_lock(&nuvo_pr->device_mutex);
            ret = nuvo_pr_device_find(req->open.device_uuid, &dev_index);
            if (ret < 0)
            {
                // failed to find device
                // TODO: do we want to request this info from control somehow?
                nuvo_mutex_unlock(&nuvo_pr->device_mutex);
                req->status = ret;
                req->callback(req);
                break;
            }

            node_index = nuvo_pr->device_list[dev_index].node_index;
            node = &nuvo_pr->node_table[node_index];

            nuvo_mutex_lock(&node->nd_mutex);
            nuvo_mutex_unlock(&nuvo_pr->device_mutex);

            if (req->open.reopen_flag == 0)
            {
                // allocate parcel definition
                pdef = nuvo_pr_pdef_alloc();
                if (pdef == NULL)
                {
                    nuvo_mutex_unlock(&node->nd_mutex);
                    req->status = -1;
                    // invoke callback directly
                    req->callback(req);
                    break;
                }
                pdef_val = atomic_load(pdef);
                pdef_val.native_pd = 0;
                pdef_val.node_index = node_index;
                atomic_store(pdef, pdef_val);
            }
            else
            {
                // We are doing a parcel reopen, the pdef already exists
                pdesc.pd = req->open.reopen_pi->parcel_desc;
                pdef = &nuvo_pr->pdef_table[pdesc.index];
                // Give the remote side a hint that this is resent op.
                req->op_retry_cnt = 1;
            }

            req->open.client_pdef = pdef;

            if (node_index == NUVO_PR_LOCAL_NODE_INDEX)
            {
                nuvo_dlist_insert_tail(&local_list, &req->list_node);
                nuvo_mutex_unlock(&node->nd_mutex);
            }
            else
            {
                ret = nuvo_pr_get_conn(node, &conn, true);
                nuvo_mutex_unlock(&node->nd_mutex);
                if (ret < 0)
                {
                    nuvo_pr_pdef_free(pdef);
                    req->status = -1;
                    req->callback(req);
                    break;
                }

                ret = nuvo_pr_cconn_enqueue_req(conn, req, &completed_list);
                nuvo_mutex_unlock(&conn->cc_mutex);
                if (ret < 0)
                {
                    req->status = ret;
                    req->callback(req);
                    break;
                }
            }
            break;

        case NUVO_OP_CLOSE:
            // determine if it is local or remote
            pdesc.pd = req->close.parcel_desc;

            ret = nuvo_pr_pdef_get(pdesc, &pdef_val);
            if (ret < 0)
            {
                NUVO_LOG(pr, 0,
                         "Translated close parcel error (no pdef) to success.",
                         req->operation);
                // Could be for a duplicate close request, make idempotent
                // by returning success.  Since we aren't going through
                // nuvo_pr_complete, set success here.
                req->status = 0;
                req->idempotent_status_flag = 1;
                req->callback(req);
                break;
            }

            if (pdef_val.outstanding_io != 0)
            {
                // TODO: this is bad news if we're closing a parcel that we have outstanding IOs on
                NUVO_PANIC("Attempting to close parcel descriptor that has outstanding IO.");
            }

            // save local parcel descriptor
            req->close.native_parcel_desc = pdef_val.native_pd;
            if (pdef_val.node_index == NUVO_PR_LOCAL_NODE_INDEX)
            {
                nuvo_dlist_insert_tail(&local_list, &req->list_node);
            }
            else
            {
                node = &nuvo_pr->node_table[pdef_val.node_index];
                nuvo_mutex_lock(&node->nd_mutex);
                ret = nuvo_pr_get_conn(node, &conn, false);
                nuvo_mutex_unlock(&node->nd_mutex);

                if (ret < 0)
                {
                    req->status = -1;
                    req->callback(req);
                    break;
                }

                ret = nuvo_pr_cconn_enqueue_req(node->conn, req,
                                                &completed_list);
                nuvo_mutex_unlock(&conn->cc_mutex);
                if (ret < 0)
                {
                    req->status = ret;
                    req->callback(req);
                    break;
                }
            }

            break;

        case NUVO_OP_ALLOC:
            // determine if it is local or remote

            nuvo_mutex_lock(&nuvo_pr->device_mutex);
            ret = nuvo_pr_device_find(req->alloc.device_uuid, &dev_index);
            if (ret < 0)
            {
                // failed to find device
                // TODO: do we want to request this info from control somehow?
                nuvo_mutex_unlock(&nuvo_pr->device_mutex);
                req->status = ret;
                req->callback(req);
                break;
            }

            node_index = nuvo_pr->device_list[dev_index].node_index;
            node = &nuvo_pr->node_table[node_index];

            nuvo_mutex_lock(&node->nd_mutex);
            nuvo_mutex_unlock(&nuvo_pr->device_mutex);

            if (node_index == NUVO_PR_LOCAL_NODE_INDEX)
            {
                nuvo_dlist_insert_tail(&local_list, &req->list_node);
                nuvo_mutex_unlock(&node->nd_mutex);
            }
            else
            {
                ret = nuvo_pr_get_conn(node, &conn, true);
                if (ret < 0)
                {
                    req->status = ret;
                    req->callback(req);
                    break;
                }

                nuvo_mutex_unlock(&node->nd_mutex);
                ret = nuvo_pr_cconn_enqueue_req(conn, req, &completed_list);
                nuvo_mutex_unlock(&conn->cc_mutex);
                if (ret < 0)
                {
                    req->status = ret;
                    req->callback(req);
                    break;
                }
            }
            break;

        case NUVO_OP_FREE:
            // determine if it is local or remote

            nuvo_mutex_lock(&nuvo_pr->device_mutex);
            ret = nuvo_pr_device_find(req->free.device_uuid, &dev_index);
            if (ret < 0)
            {
                // failed to find device
                // TODO: do we want to request this info from control somehow?
                nuvo_mutex_unlock(&nuvo_pr->device_mutex);
                req->status = ret;
                req->callback(req);
                break;
            }

            node_index = nuvo_pr->device_list[dev_index].node_index;
            node = &nuvo_pr->node_table[node_index];

            nuvo_mutex_lock(&node->nd_mutex);
            nuvo_mutex_unlock(&nuvo_pr->device_mutex);

            if (node_index == NUVO_PR_LOCAL_NODE_INDEX)
            {
                nuvo_dlist_insert_tail(&local_list, &req->list_node);
                nuvo_mutex_unlock(&node->nd_mutex);
            }
            else
            {
                ret = nuvo_pr_get_conn(node, &conn, true);
                if (ret < 0)
                {
                    req->status = ret;
                    req->callback(req);
                    break;
                }

                nuvo_mutex_unlock(&node->nd_mutex);
                ret = nuvo_pr_cconn_enqueue_req(conn, req, &completed_list);
                nuvo_mutex_unlock(&conn->cc_mutex);
                if (ret < 0)
                {
                    req->status = ret;
                    req->callback(req);
                    break;
                }
            }
            break;

        case NUVO_OP_DEV_INFO:
            // determine if it is local or remote

            nuvo_mutex_lock(&nuvo_pr->device_mutex);
            ret = nuvo_pr_device_find(req->dev_info.device_uuid, &dev_index);
            if (ret < 0)
            {
                // failed to find device
                // TODO: do we want to request this info from control somehow?
                nuvo_mutex_unlock(&nuvo_pr->device_mutex);
                req->status = ret;
                req->callback(req);
                break;
            }

            node_index = nuvo_pr->device_list[dev_index].node_index;
            node = &nuvo_pr->node_table[node_index];

            nuvo_mutex_lock(&node->nd_mutex);
            nuvo_mutex_unlock(&nuvo_pr->device_mutex);

            if (node_index == NUVO_PR_LOCAL_NODE_INDEX)
            {
                nuvo_dlist_insert_tail(&local_list, &req->list_node);
                nuvo_mutex_unlock(&node->nd_mutex);
            }
            else
            {
                ret = nuvo_pr_get_conn(node, &conn, true);
                if (ret < 0)
                {
                    req->status = ret;
                    req->callback(req);
                    break;
                }

                nuvo_mutex_unlock(&node->nd_mutex);
                ret = nuvo_pr_cconn_enqueue_req(conn, req, &completed_list);
                nuvo_mutex_unlock(&conn->cc_mutex);
                if (ret < 0)
                {
                    req->status = ret;
                    req->callback(req);
                    break;
                }
            }
            break;
        }
    }

    // submit requests to local IO and to connection IO
    nuvo_pm_submit(&local_list);

    while ((req = nuvo_dlist_remove_head_object(&completed_list,
                                                struct nuvo_io_request,
                                                list_node)) != NULL)
    {
        nuvo_pr_complete(req);
    }
}

void nuvo_pr_complete(struct nuvo_io_request *req)
{
    nuvo_return_t           ret;
    union parcel_descriptor pdesc;
    struct nuvo_pr_pdef     pdef_val;

    // only do completion handlers for local requests

    if (req->sconn == NULL)
    {
        // Update error codes to success for certain idempotent operations
        nuvo_pr_idempotent_status_set(req);

        switch (req->operation)
        {
        case NUVO_OP_OPEN:
            if (req->status < 0)
            {
                // Only free pdef if the initial parcel open fails. If a reopen
                // fails, there could be existing references to the pdef.
                if (req->open.reopen_flag == 0)
                {
                    nuvo_pr_pdef_free(req->open.client_pdef);
                }
                req->open.parcel_desc = NUVO_PR_INVALID32;
            }
            else
            {
                pdef_val = atomic_load(req->open.client_pdef);
                // update parcel definition
                pdef_val.native_pd = req->open.parcel_desc;
                atomic_store(req->open.client_pdef, pdef_val);
                // put routed parcel descriptor in request
                req->open.parcel_desc = nuvo_pr_pdef_to_pdesc(
                    req->open.client_pdef).pd;
                req->status = 0;
            }
            break;

        case NUVO_OP_CLOSE:
            // if close
            if (req->status >= 0)
            {
                // do pdef clean-up
                pdesc.pd = req->close.parcel_desc;

                ret = nuvo_pr_pdef_get(pdesc, &pdef_val);
                if (ret < 0)
                {
                    // pdef was already freed, can happen if duplicate close
                    // requests are issued.
                    NUVO_LOG(pr, 0,
                             "Duplicate close request received %p, parcel definition already removed.",
                             (void *)req);
                }
                else
                {
                    if (pdef_val.outstanding_io != 0)
                    {
                        // TODO: this is bad news if we're closing a parcel that we have outstanding IOs on
                        NUVO_PANIC("Closing parcel descriptor with outstanding IOs.");
                    }

                    // everyting looks good, free parcel def
                    nuvo_pr_pdef_free(&nuvo_pr->pdef_table[pdesc.index]);
                }
            }
            break;

        case NUVO_OP_READ:
        case NUVO_OP_READ_VERIFY:
        case NUVO_OP_WRITE:
            pdesc.pd = req->rw.parcel_desc;
            nuvo_pr_pdef_add_outstanding(pdesc, -1);
            break;

        case NUVO_OP_ALLOC:
        case NUVO_OP_FREE:
        case NUVO_OP_DEV_INFO:
            break;
        }
    }

    req->callback(req);
}

extern inline void nuvo_pr_submit_req(struct nuvo_io_request *req);

nuvo_return_t nuvo_pr_server_sock_init(uint_fast16_t server_port)
{
    int ret;

    // start server listener
    nuvo_pr->server_listen_sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK,
                                         0);
    if (nuvo_pr->server_listen_sock < 0)
    {
        // TODO: error codes and such
        return (-NUVO_ENOMEM);
    }

    // Set this to reuse so we can use a port passed in in TIMED_WAIT
    // This lets us use custom ephemeral ports for tests.
    int enable = 1;
    if (setsockopt(nuvo_pr->server_listen_sock, SOL_SOCKET, SO_REUSEADDR,
                   &enable, sizeof(int)) < 0)
    {
        // TODO: error codes and such
        close(nuvo_pr->server_listen_sock);
        return (-NUVO_E_SOCK_OPT);
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    addr.sin_addr.s_addr = 0;   // bind to 0.0.0.0

    ret = bind(nuvo_pr->server_listen_sock, (struct sockaddr *)&addr,
               sizeof(addr));
    if (ret != 0)
    {
        // TODO: error codes and such
        close(nuvo_pr->server_listen_sock);
        return (-NUVO_E_BIND);
    }

    ret = listen(nuvo_pr->server_listen_sock, NUVO_SERVER_BACKLOG);
    if (ret != 0)
    {
        // TODO: error codes and such
        close(nuvo_pr->server_listen_sock);
        return (-NUVO_E_LISTEN);
    }

    return (0);
}

nuvo_return_t nuvo_pr_conn_mgr_init(void)
{
    nuvo_return_t ret;

    nuvo_pr->cm_info.conn_recovery_cnt = 0;

    // init mutexes
    ret = nuvo_mutex_init(&nuvo_pr->cm_info.cm_work_mutex);
    if (ret != 0)
    {
        return (-NUVO_ENOMEM);
    }
    ret = nuvo_cond_init(&nuvo_pr->cm_info.cm_work_cv);
    if (ret != 0)
    {
        nuvo_mutex_destroy(&nuvo_pr->cm_info.cm_work_mutex);
        return (-NUVO_ENOMEM);
    }

    // Setup epoll for recovering failed connections
    nuvo_pr->cm_info.recovery_epoll_fd = epoll_create1(0);
    if (nuvo_pr->cm_info.recovery_epoll_fd == -1)
    {
        nuvo_mutex_destroy(&nuvo_pr->cm_info.cm_work_mutex);
        nuvo_cond_destroy(&nuvo_pr->cm_info.cm_work_cv);
        return (-NUVO_ENOMEM);
    }

    ret = pthread_create(&nuvo_pr->conn_mgr_thread, NULL,
                         nuvo_pr_conn_mgr_thread, NULL);
    if (ret < 0)
    {
        nuvo_mutex_destroy(&nuvo_pr->cm_info.cm_work_mutex);
        nuvo_cond_destroy(&nuvo_pr->cm_info.cm_work_cv);
        close(nuvo_pr->cm_info.recovery_epoll_fd);
        return (-NUVO_ENOMEM);
    }

    return (0);
}

void nuvo_pr_conn_mgr_destroy(void)
{
    // This wakes up the conn_mgr thread, and since nuvo_pr->shutdown_flag
    // is set, the conn_mgr thread will exit cleanly.
    nuvo_mutex_lock(&nuvo_pr->cm_info.cm_work_mutex);
    nuvo_pr->cm_info.conn_recovery_cnt++;
    nuvo_cond_signal(&nuvo_pr->cm_info.cm_work_cv);
    nuvo_mutex_unlock(&nuvo_pr->cm_info.cm_work_mutex);
    // Or just send a kill signal
    //pthread_kill(nuvo_pr->conn_mgr_thread, SIGUSR1);

    pthread_join(nuvo_pr->conn_mgr_thread, NULL);

    close(nuvo_pr->cm_info.recovery_epoll_fd);

    // destroy mutexes
    nuvo_mutex_destroy(&nuvo_pr->cm_info.cm_work_mutex);
    nuvo_cond_destroy(&nuvo_pr->cm_info.cm_work_cv);
}

uint64_t nuvo_pr_cconn_get_backoff_ns(struct nuvo_pr_client_conn *conn)
{
    uint64_t backoff_sec = 0;
    uint32_t once_a_sec_cnt = NUVO_PR_CONN_BACKOFF_WAIT_SECS;
    uint32_t scale_up_sec = NUVO_PR_CONN_BACKOFF_EXTRA_SECS;


    // Basically retry every second for the first minute,
    // then start backing off until we are retrying once every minute.
    if (conn->backoff_cnt <= once_a_sec_cnt)
    {
        backoff_sec = NUVO_PR_CONN_MIN_RETRY_SECS;
    }
    else if (conn->backoff_cnt <= once_a_sec_cnt +
             NUVO_PR_CONN_MAX_RETRY_SECS / scale_up_sec)
    {
        backoff_sec = (conn->backoff_cnt - once_a_sec_cnt) * scale_up_sec;
    }
    else
    {
        backoff_sec = NUVO_PR_CONN_MAX_RETRY_SECS;
    }

    return (backoff_sec * 1000000000ull);
}

struct nuvo_pr_client_conn *nuvo_pr_get_recovery_cconn()
{
    struct nuvo_pr_client_conn *conn;

    nuvo_mutex_lock(&nuvo_pr->client_conn_mutex);

    conn = nuvo_dlist_get_head_object(&nuvo_pr->client_conn_error_list,
                                      struct nuvo_pr_client_conn, list_node);
    while (conn != NULL)
    {
        if ((conn->cc_state == NUVO_CCCS_ERROR) ||
            (conn->cc_state == NUVO_CCCS_RESEND_READY))
        {
            uint_fast64_t now = nuvo_get_timestamp();
            if ((now - conn->recovery_start_ts) <
                nuvo_pr_cconn_get_backoff_ns(conn))
            {
                // Skip connections that we have retried in the last second.
                continue;
            }
            else
            {
                // Found a connection to recover
                break;
            }
        }

        conn = nuvo_dlist_get_next_object(&nuvo_pr->client_conn_error_list,
                                          conn, struct nuvo_pr_client_conn,
                                          list_node);
    }

    nuvo_mutex_unlock(&nuvo_pr->client_conn_mutex);

    return (conn);
}

void nuvo_pr_cconn_recovery_start(struct nuvo_pr_client_conn *conn)
{
    int ret;

    NUVO_ASSERT_MUTEX_HELD(&conn->cc_mutex);
    NUVO_ASSERT(conn->cc_state == NUVO_CCCS_ERROR);

    NUVO_LOG(pr, 0, "Connection Recovery - conn %d recovery start.",
             GET_PR_CCONN_IDX(conn));

    conn->recovery_start_ts = nuvo_get_timestamp();
    conn->backoff_cnt++;

    // Remove from client thread epoll, will be added to conn_mgr epoll later.
    ret = nuvo_pr_cconn_epoll_remove(conn, nuvo_pr->client_epoll_fd);
    if (ret < 0)
    {
        NUVO_ERROR_PRINT(
            "Connection Recovery - conn %d hit error during epoll_ctl del of socket %d.",
            GET_PR_CCONN_IDX(conn), conn->sock_fd);
        // Since we are in error state, we will try again later.
        return;
    }
    nuvo_pr_update_volumes_health(conn, false);

    nuvo_pr_cconn_set_state(conn, NUVO_CCCS_RECONNECT);

    NUVO_LOG(pr, 50,
             "Connection Recovery - conn %d moving reqs to retry queue.",
             GET_PR_CCONN_IDX(conn));
    // move all pending and queued io to req_retry_list
    nuvo_pr_cconn_move_to_retry_q(conn);

    NUVO_LOG(pr, 50, "Connection Recovery - conn %d recovering socket.",
             GET_PR_CCONN_IDX(conn));
    // do socket tear down and reconnect
    ret = nuvo_pr_cconn_recover_socket(conn);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT(
            "Connection Recovery - conn %d Error during socket recovery: %d.",
            GET_PR_CCONN_IDX(conn), ret);

        // We tried, retried, and gave up.  Close the connection.
        nuvo_pr_cconn_recovery_failed(conn);

        return;
    }

    // In the common path, the rest of the recovery happens after epoll
    // informs us the socket is up.

    return;
}

void nuvo_pr_cconn_recovery_resend(struct nuvo_pr_client_conn *conn)
{
    int ret;

    NUVO_ASSERT_MUTEX_HELD(&conn->cc_mutex);
    NUVO_ASSERT(conn->cc_state == NUVO_CCCS_RESEND_READY);

    nuvo_pr_cconn_set_state(conn, NUVO_CCCS_RESENDING);

    // Resend parcel opens and exit if we are in the RESEND_CONFIG phase.
    if (conn->cc_resend_phase == NUVO_RESEND_CONFIG)
    {
        NUVO_LOG(pr, 50,
                 "Connection Recovery - conn %d resending parcel open requests.",
                 GET_PR_CCONN_IDX(conn));
        // Send all open requests to reestablish state
        ret = nuvo_pr_cconn_resend_opens(conn);

        if ((ret < 0) || (conn->cc_state == NUVO_CCCS_ERROR))
        {
            NUVO_ERROR_PRINT(
                "Connection Recovery - conn %d Error during resend of in flight requests: %d.",
                GET_PR_CCONN_IDX(conn), ret);

            return;
        }
        return;
    }

    NUVO_ASSERT(conn->cc_resend_phase == NUVO_RESEND_DATA);

    NUVO_LOG(pr, 50,
             "Connection Recovery - conn %d updating parcel descriptors.",
             GET_PR_CCONN_IDX(conn));

    nuvo_pr_cconn_update_pdescs(conn);

    NUVO_LOG(pr, 50,
             "Connection Recovery - conn %d resending in flight requests.",
             GET_PR_CCONN_IDX(conn));
    // Send all requests that were in flight at the time of the error
    ret = nuvo_pr_cconn_resend_reqs(conn);

    // It's possible that we hit another error while resending. In this
    // case we want to bail out and start the recovery process over.
    if ((ret < 0) || (conn->cc_state == NUVO_CCCS_ERROR))
    {
        NUVO_ERROR_PRINT(
            "Connection Recovery - conn %d Error during resend of in flight requests: %d.",
            GET_PR_CCONN_IDX(conn), ret);

        return;
    }

    // Make sure the retry queue is empty.
    NUVO_ASSERT(nuvo_dlist_get_head_object(&conn->req_retry_list, struct
                                           nuvo_io_request, list_node) == NULL);

    // All reqs in flight when error occurred have successfully been sent.
    nuvo_pr_cconn_set_state(conn, NUVO_CCCS_CONNECTED);
    conn->cc_resend_phase = NUVO_RESEND_NONE;

    // Decrement recovery cnt after changing state to connected, because if we
    // hit another error before completing, we will bump recovery cnt again.
    nuvo_mutex_lock(&nuvo_pr->cm_info.cm_work_mutex);
    nuvo_pr->cm_info.conn_recovery_cnt--;
    nuvo_mutex_unlock(&nuvo_pr->cm_info.cm_work_mutex);

    // Check the socket for any responses while we were in the
    // RECOVERING state.  Only an issue if we don't send any more reqs.
    ret = nuvo_pr_cconn_check_recv(conn);
    if ((ret < 0) || (conn->cc_state != NUVO_CCCS_CONNECTED))
    {
        NUVO_ERROR_PRINT(
            "Connection Recovery - conn %d Error during socket receive check: %d.",
            GET_PR_CCONN_IDX(conn), ret);

        return;
    }

    NUVO_LOG(pr, 50, "Connection Recovery - conn %d resending queued requests.",
             GET_PR_CCONN_IDX(conn));
    // Send any reqs that we queued while the socket reconnect was in
    // progress. Since we are now in the CONNECTED state, this will
    // process reqs from the wait list.
    ret = nuvo_pr_cconn_resend_reqs(conn);
    if ((ret < 0) || (conn->cc_state != NUVO_CCCS_CONNECTED))
    {
        NUVO_ERROR_PRINT(
            "Connection Recovery - conn %d Error during resend of queued requests: %d.",
            GET_PR_CCONN_IDX(conn), ret);

        return;
    }

    nuvo_pr_cconn_recovery_complete(conn);
}

void nuvo_pr_cconn_move_to_retry_q(struct nuvo_pr_client_conn *conn)
{
    struct nuvo_io_request *req;
    int req_rw_cnt = 0;
    int req_total_cnt = 0;

    // Include req that was currently being sent. conn->send_req may not be on
    // any list.
    if (conn->send_req)
    {
        if (!nuvo_dlnode_on_list(&conn->send_req->list_node))
        {
            nuvo_dlist_insert_tail(&conn->req_pending_list,
                                   &conn->send_req->list_node);
        }
    }

    // It is possible that we hit another error while we were recovering.
    // In this case, the retry list may already have reqs in it.
    // So we need to grab from the tail of pending list and insert
    // at the head of retry list, the reverse won't work.
    while ((req = nuvo_dlist_remove_tail_object(&conn->req_pending_list,
                                                struct nuvo_io_request,
                                                list_node)) != NULL)
    {
        req->op_retry_cnt++;
        nuvo_dlist_insert_head(&conn->req_retry_list, &req->list_node);

        if ((req->operation == NUVO_OP_READ) ||
            (req->operation == NUVO_OP_READ_VERIFY) ||
            (req->operation == NUVO_OP_WRITE))
        {
            req_rw_cnt++;
        }
        else
        {
            NUVO_LOG(pr, 50,
                     "Connection Recovery - conn %d had request %p in flight, op type %d, attempt %d",
                     GET_PR_CCONN_IDX(conn), (void *)req, req->operation,
                     req->op_retry_cnt);
        }
        req_total_cnt++;
    }

    // If there are any config resend ops, remove them from the list and free
    // the resources.  They will be sent again during recovery.
    req = nuvo_dlist_get_head_object(&conn->req_retry_list,
                                     struct nuvo_io_request, list_node);
    while (req)
    {
        struct nuvo_io_request *req_next;
        req_next = nuvo_dlist_get_next_object(&conn->req_retry_list, req,
                                              struct nuvo_io_request,
                                              list_node);

        if (nuvo_pr_is_resend_config_req(req))
        {
            //remove and free the req
            nuvo_dlist_remove(&req->list_node);
            nuvo_pr_client_req_free(req);
            NUVO_LOG(pr, 10,
                     "Connection Recovery - conn %d config request removed from queue, request will be resent after connection is reestablished.",
                     GET_PR_CCONN_IDX(conn));
        }

        req = req_next;
    }


    NUVO_LOG(pr, 0,
             "Connection Recovery - conn %d had %d read/write requests outstanding during socket failure.",
             GET_PR_CCONN_IDX(conn), req_rw_cnt);
    if (req_total_cnt != req_rw_cnt)
    {
        NUVO_LOG(pr, 0,
                 "Connection Recovery - conn %d had %d requests that weren't reads/writes during socket failure.",
                 GET_PR_CCONN_IDX(conn), req_total_cnt - req_rw_cnt);
    }
}

nuvo_return_t nuvo_pr_cconn_recover_socket(struct nuvo_pr_client_conn *conn)
{
    int ret;

    NUVO_ASSERT(conn->cc_state == NUVO_CCCS_RECONNECT);

    NUVO_LOG(pr, 50, "Connection Recovery - conn %d socket recovery started.",
             GET_PR_CCONN_IDX(conn));

    // TODO: how many times do we want to retry (if any)?
    int retry_cnt = 0;
    ret = -1;
    while ((ret != 0) && (retry_cnt < NUVO_PR_MAX_CONN_RETRIES))
    {
        retry_cnt++;
        if (conn->sock_fd >= 0)
        {
            ret = close(conn->sock_fd);
            if (ret != 0)
            {
                continue;
            }
        }
        conn->sock_fd = -1;

        // open socket, using the connection's exsiting node_desc
        ret = nuvo_pr_cconn_open(conn, conn->node_desc);
    }

    return (ret);
}

void nuvo_pr_cconn_update_pdescs(struct nuvo_pr_client_conn *conn)
{
    struct nuvo_io_request *req;
    struct nuvo_dlist      *req_list = &conn->req_retry_list;

    req = nuvo_dlist_get_head_object(req_list, struct nuvo_io_request,
                                     list_node);
    // Iterate through all the items on the retry queue.  Once finished with
    // the retry queue, step through the wait list as well.
    while (req)
    {
        union parcel_descriptor pdesc;
        struct nuvo_pr_pdef     pdef_val;

        switch (req->operation)
        {
        case NUVO_OP_READ:
        case NUVO_OP_READ_VERIFY:
        case NUVO_OP_WRITE:
            pdesc.pd = req->rw.parcel_desc;
            if (nuvo_pr_pdef_get(pdesc, &pdef_val) >= 0)
            {
                if (req->rw.native_parcel_desc != pdef_val.native_pd)
                {
                    NUVO_LOG(pr, 50,
                             "Connection Recovery - conn %d updated r/w parcel desc from %d to %d.",
                             GET_PR_CCONN_IDX(conn),
                             req->rw.native_parcel_desc, pdef_val.native_pd);
                    req->rw.native_parcel_desc = pdef_val.native_pd;
                }
            }
            else
            {
                NUVO_ASSERT(!"Parcel Definition not found!");
            }
            break;

        case NUVO_OP_CLOSE:
            pdesc.pd = req->close.parcel_desc;
            if (nuvo_pr_pdef_get(pdesc, &pdef_val) >= 0)
            {
                if (req->close.native_parcel_desc != pdef_val.native_pd)
                {
                    NUVO_LOG(pr, 50,
                             "Connection Recovery - conn %d updated close parcel desc from %d to %d.",
                             GET_PR_CCONN_IDX(conn),
                             req->close.native_parcel_desc, pdef_val.native_pd);
                    req->close.native_parcel_desc = pdef_val.native_pd;
                }
            }
            else
            {
                NUVO_ASSERT(!"Parcel Definition not found!");
            }
            break;

        default:
            break;
        }

        req = nuvo_dlist_get_next_object(req_list, req, struct nuvo_io_request,
                                         list_node);
        if ((req == NULL) && (req_list != &conn->req_wait_list))
        {
            // Process the pending list once we're done with the retry list.
            req_list = &conn->req_wait_list;
            req = nuvo_dlist_get_head_object(req_list, struct nuvo_io_request,
                                             list_node);
        }
    }

    return;
}

nuvo_return_t nuvo_pr_cconn_resend_reqs(struct nuvo_pr_client_conn *conn)
{
    int ret = 0;
    struct nuvo_io_request *req;
    struct nuvo_dlist       completed_list;

    nuvo_dlist_init(&completed_list);

    NUVO_ASSERT((conn->cc_state == NUVO_CCCS_RESENDING) ||
                (conn->cc_state == NUVO_CCCS_CONNECTED));

    while (ret == 0)
    {
        // When we are in the recovering state, we grab reqs from the
        // retry list instead of the normal wait list
        ret = nuvo_pr_cconn_process_send(conn, &completed_list);

        if (ret != 0)
        {
            break;
        }

        if (conn->cc_state == NUVO_CCCS_CONNECTED)
        {
            break;
        }

        // Once the retry_list is empty, we're done.
        if (nuvo_dlist_get_head_object(&conn->req_retry_list,
                                       struct nuvo_io_request,
                                       list_node) == NULL)
        {
            break;
        }
    }

    nuvo_mutex_unlock(&conn->cc_mutex);
    while ((req = nuvo_dlist_remove_head_object(&completed_list,
                                                struct nuvo_io_request,
                                                list_node)) != NULL)
    {
        nuvo_pr_complete(req);
    }
    nuvo_mutex_lock(&conn->cc_mutex);

    return (ret);
}

nuvo_return_t nuvo_pr_cconn_check_recv(struct nuvo_pr_client_conn *conn)
{
    int ret = 0;
    struct nuvo_io_request *req;
    struct nuvo_dlist       completed_list;

    nuvo_dlist_init(&completed_list);

    NUVO_ASSERT(conn->cc_state == NUVO_CCCS_CONNECTED);

    ret = nuvo_pr_cconn_process_recv(conn, &completed_list);

    // Send acks for anything successfully put on the completed list
    nuvo_mutex_unlock(&conn->cc_mutex);
    while ((req = nuvo_dlist_remove_head_object(&completed_list,
                                                struct nuvo_io_request,
                                                list_node)) != NULL)
    {
        nuvo_pr_complete(req);
    }
    nuvo_mutex_lock(&conn->cc_mutex);

    return (ret);
}

void nuvo_pr_cconn_recovery_complete(struct nuvo_pr_client_conn *conn)
{
    int ret;

    NUVO_ASSERT_MUTEX_HELD(&conn->cc_mutex);
    NUVO_ASSERT(conn->cc_state == NUVO_CCCS_CONNECTED);

    // Move from error list back to active list
    nuvo_mutex_lock(&nuvo_pr->client_conn_mutex);
    nuvo_dlist_remove(&conn->list_node);
    nuvo_dlist_insert_tail(&nuvo_pr->client_conn_active_list, &conn->list_node);
    nuvo_mutex_unlock(&nuvo_pr->client_conn_mutex);

    // TODO: Think about potentially missing events when switching to the epoll
    // on the client thread.  Won't be an issue when/if we move the retry queue
    // to the RL layer.  Then the switch won't happen until no I/O in flight.

    // Move the connection from the conn_mgr epoll to the client_thread epoll
    ret = nuvo_pr_cconn_epoll_move(conn, nuvo_pr->cm_info.recovery_epoll_fd,
                                   nuvo_pr->client_epoll_fd);
    if (ret < 0)
    {
        // So close to healthy, but start over at the beginning.
        nuvo_pr_cconn_set_state(conn, NUVO_CCCS_ERROR);
        return;
    }

    conn->backoff_cnt = 0;

    nuvo_pr_update_volumes_health(conn, true);

    NUVO_LOG(pr, 0, "Connection Recovery - conn %d recovery successful",
             GET_PR_CCONN_IDX(conn));
}

void nuvo_pr_cconn_recovery_failed(struct nuvo_pr_client_conn *conn)
{
    struct nuvo_dlist completed_list;

    nuvo_dlist_init(&completed_list);

    // Decrement recovery cnt
    nuvo_mutex_lock(&nuvo_pr->cm_info.cm_work_mutex);
    nuvo_pr->cm_info.conn_recovery_cnt--;
    nuvo_mutex_unlock(&nuvo_pr->cm_info.cm_work_mutex);

    // shutdown, and preserve the original close err/reason.
    nuvo_pr_cconn_shutdown(conn, &completed_list, conn->prev_close_err,
                           conn->prev_close_reason);

    NUVO_LOG(pr, 0, "Connection Recovery - conn %d recovery failed",
             GET_PR_CCONN_IDX(conn));
}

struct nuvo_pr_server_conn *nuvo_pr_get_recovery_sconn()
{
    struct nuvo_pr_server_conn *sconn;

    nuvo_mutex_lock(&nuvo_pr->server_conn_mutex);

    sconn = nuvo_dlist_get_head_object(&nuvo_pr->server_conn_active_list,
                                       struct nuvo_pr_server_conn, list_node);
    while (sconn != NULL)
    {
        if (sconn->sc_state == NUVO_SCCS_ERROR)
        {
            // Found a connection to recover
            break;
        }

        sconn = nuvo_dlist_get_next_object(&nuvo_pr->server_conn_active_list,
                                           sconn, struct nuvo_pr_server_conn,
                                           list_node);
    }

    nuvo_mutex_unlock(&nuvo_pr->server_conn_mutex);

    return (sconn);
}

void nuvo_pr_sconn_recovery_start(struct nuvo_pr_server_conn *conn)
{
    NUVO_ASSERT_MUTEX_HELD(&conn->sc_mutex);
    NUVO_ASSERT(conn->sc_state == NUVO_SCCS_ERROR);

    // For server connections, recovery means throwing everything
    // away and successfully closing the connection.
    if (conn->sc_state != NUVO_SCCS_ERROR)
    {
        NUVO_ERROR_PRINT(
            "Connection Recovery - conn %d Error, recovery called on server connection not in error state, state: %d",
            GET_PR_SCONN_IDX(conn), conn->sc_state);

        return;
    }

    NUVO_LOG(pr, 0, "Connection Recovery - conn %d recovery start.",
             GET_PR_SCONN_IDX(conn));

    nuvo_mutex_lock(&nuvo_pr->cm_info.cm_work_mutex);
    nuvo_pr->cm_info.conn_recovery_cnt--;
    nuvo_mutex_unlock(&nuvo_pr->cm_info.cm_work_mutex);

    // Just call shutdown for now, connection already has error info.
    nuvo_pr_sconn_shutdown(conn, conn->prev_close_err,
                           conn->prev_close_reason);

    NUVO_LOG(pr, 0, "Connection Recovery - conn %d recovery successful.",
             GET_PR_SCONN_IDX(conn));

    return;
}

bool nuvo_pr_is_retriable_req(struct nuvo_io_request *req)
{
    switch (req->operation)
    {
    case NUVO_OP_READ:
    case NUVO_OP_READ_VERIFY:
    case NUVO_OP_WRITE:
    case NUVO_OP_OPEN:
    case NUVO_OP_CLOSE:
    case NUVO_OP_FREE:
        return (true);

    case NUVO_OP_ALLOC:
    case NUVO_OP_DEV_INFO:
        return (false);
    }

    NUVO_ASSERT(!"Update this function, can the PM handle a retry of this op?");
    return (false);
}

nuvo_return_t nuvo_pr_socket_poll_wait(int sock_fd, int timeout)
{
    int           ret;
    struct pollfd pfd;

    pfd.fd = sock_fd;
    pfd.events = POLLIN | POLLPRI | POLLOUT | POLLRDHUP | POLLHUP | POLLERR;

    timeout = timeout * 1000; // convert from seconds to ms

    ret = poll(&pfd, 1, timeout);
    if (ret > 0)
    {
        if (pfd.revents & (EPOLLRDHUP | EPOLLERR | EPOLLHUP))
        {
            // Failed to establish connection
            NUVO_LOG(pr, 20, "Poll for socket failed due to event(s): %x.",
                     pfd.revents);
            ret = -NUVO_E_CONNECT;
        }
        else
        {
            NUVO_LOG(pr, 20, "Poll returned succesfully, connection ready");
            ret = 0;
        }
    }
    else if (ret == 0)
    {
        NUVO_ERROR_PRINT("Poll for socket timed out.");
        ret = -NUVO_E_CONNECT;
    }
    else
    {
        NUVO_ERROR_PRINT("Poll for socket failed.");
        ret = -errno;
    }

    return (ret);
}

nuvo_return_t nuvo_pr_cconn_epoll_add(struct nuvo_pr_client_conn *conn,
                                      int                         epoll_fd)
{
    return (nuvo_pr_cconn_epoll_move(conn, -1, epoll_fd));
}

nuvo_return_t nuvo_pr_cconn_epoll_remove(struct nuvo_pr_client_conn *conn,
                                         int                         epoll_fd)
{
    return (nuvo_pr_cconn_epoll_move(conn, epoll_fd, -1));
}

nuvo_return_t nuvo_pr_cconn_epoll_move(struct nuvo_pr_client_conn *conn,
                                       int epoll_fd_from, int epoll_fd_to)
{
    int ret;
    struct epoll_event      event;
    union nuvo_pr_event_tag etag;

    if (epoll_fd_from >= 0)
    {
        ret = epoll_ctl(epoll_fd_from, EPOLL_CTL_DEL, conn->sock_fd, &event);
        if (ret < 0)
        {
            if (errno == ENOENT)
            {
                // Since it's already deleted, treat it as a success
                ret = 0;
                NUVO_LOG(pr, 50,
                         "Connection %d called epoll_ctl del on already deleted socket %d.",
                         GET_PR_CCONN_IDX(conn), conn->sock_fd);
            }
            else
            {
                NUVO_ERROR_PRINT(
                    "Connection %d encountered error during epoll_ctl del of socket %d.",
                    GET_PR_CCONN_IDX(conn), conn->sock_fd);
                return (-NUVO_E_EPOLL_CTL);
            }
        }
    }
    if (epoll_fd_to >= 0)
    {
        etag.conn_index = GET_PR_CCONN_IDX(conn);
        etag.conn_gen = conn->cc_gen;
        event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLHUP | EPOLLERR |
                       EPOLLET;
        event.data.u64 = etag.u64;

        ret = epoll_ctl(epoll_fd_to, EPOLL_CTL_ADD, conn->sock_fd, &event);
        if (ret < 0)
        {
            if (errno == EEXIST)
            {
                // Since it's already been added, treat it as a success
                ret = 0;
                NUVO_ERROR_PRINT(
                    "Called epoll_ctl add on already existing client connection %d socket %d.",
                    GET_PR_CCONN_IDX(conn), conn->sock_fd);
            }
            else
            {
                NUVO_ERROR_PRINT(
                    "Error during epoll_ctl add of client connection %d socket %d.",
                    GET_PR_CCONN_IDX(conn), conn->sock_fd);
                return (-NUVO_E_EPOLL_CTL);
            }
        }
    }

    return (0);
}

bool nuvo_pr_is_resend_config_req(struct nuvo_io_request *req)
{
    // If we start sending other config requests, this list could grow.
    if ((req->operation == NUVO_OP_OPEN) && (req->open.reopen_flag > 0))
    {
        return (true);
    }

    return (false);
}

struct nuvo_pr_parcel_info *nuvo_pr_find_parcel_open_info(uint32_t                    parcel_desc,
                                                          struct nuvo_pr_client_conn *cconn)
{
    NUVO_ASSERT_MUTEX_HELD(&cconn->cc_mutex);

    struct nuvo_pr_parcel_info *parcel_info;

    // Check the open parcel list
    parcel_info = nuvo_dlist_get_head_object(&cconn->open_parcel_list,
                                             struct nuvo_pr_parcel_info,
                                             list_node);
    while (parcel_info)
    {
        if (parcel_info->parcel_desc == parcel_desc)
        {
            return (parcel_info);
        }

        parcel_info = nuvo_dlist_get_next_object(&cconn->open_parcel_list,
                                                 parcel_info,
                                                 struct nuvo_pr_parcel_info,
                                                 list_node);
    }

    // Check the parcel list generated during connection recovery.
    parcel_info = nuvo_dlist_get_head_object(&cconn->reopen_parcel_list,
                                             struct nuvo_pr_parcel_info,
                                             list_node);
    while (parcel_info)
    {
        if (parcel_info->parcel_desc == parcel_desc)
        {
            return (parcel_info);
        }

        parcel_info = nuvo_dlist_get_next_object(&cconn->reopen_parcel_list,
                                                 parcel_info,
                                                 struct nuvo_pr_parcel_info,
                                                 list_node);
    }

    return (NULL);
}

nuvo_return_t nuvo_pr_add_parcel_open_info(struct nuvo_io_request     *req,
                                           struct nuvo_pr_client_conn *cconn)
{
    NUVO_ASSERT_MUTEX_HELD(&cconn->cc_mutex);

    struct nuvo_pr_parcel_info *parcel_info;
    uint32_t parcel_desc;

    // Can't grab the parcel_desc off the req directly yet, it still has
    // the remote native parcel descriptor.
    parcel_desc = nuvo_pr_pdef_to_pdesc(req->open.client_pdef).pd;

    parcel_info = nuvo_pr_find_parcel_open_info(parcel_desc, cconn);
    if (!parcel_info)
    {
        // Alloc new one
        parcel_info = malloc(sizeof(struct nuvo_pr_parcel_info));
        if (!parcel_info)
        {
            NUVO_ERROR_PRINT(
                "Failed to allocate parcel info after parcel open");
            return (-NUVO_ENOMEM);
        }
        nuvo_dlnode_init(&parcel_info->list_node);
        NUVO_LOG(pr, 50, "Parcel open info allocated for parcel_desc: %d",
                 parcel_desc);

        nuvo_dlist_insert_tail(&cconn->open_parcel_list,
                               &parcel_info->list_node);
    }

    parcel_info->parcel_desc = parcel_desc;

    uuid_copy(parcel_info->parcel_uuid, req->open.parcel_uuid);
    uuid_copy(parcel_info->device_uuid, req->open.device_uuid);
    uuid_copy(parcel_info->vol_uuid, req->open.volume_uuid);

    NUVO_LOG(pr, 50, "Conn %d added parcel info for parcel desc: %d.",
             GET_PR_CCONN_IDX(cconn), parcel_info->parcel_desc);

    return (0);
}

void nuvo_pr_remove_parcel_open_info(uint32_t                    parcel_desc,
                                     struct nuvo_pr_client_conn *cconn)
{
    NUVO_ASSERT_MUTEX_HELD(&cconn->cc_mutex);

    NUVO_LOG(pr, 50, "Conn %d removing parcel info for parcel desc: %d.",
             GET_PR_CCONN_IDX(cconn), parcel_desc);

    struct nuvo_pr_parcel_info *parcel_info;

    parcel_info = nuvo_pr_find_parcel_open_info(parcel_desc,
                                                cconn);
    if (!parcel_info)
    {
        return;
    }
    nuvo_dlist_remove(&parcel_info->list_node);
    free(parcel_info);
}

void nuvo_pr_set_vol_notify_fp(nuvo_return_t
                               (*vol_notify_fp)(const uuid_t, uuid_t,
                                                enum nuvo_pr_parcel_status))
{
    nuvo_pr->cm_info.vol_parcel_notify = vol_notify_fp;
}

void nuvo_pr_update_volumes_health(struct nuvo_pr_client_conn *cconn,
                                   bool                        healthy)
{
    nuvo_return_t ret;
    struct nuvo_pr_parcel_info *parcel_info;
    enum nuvo_pr_parcel_status  parcel_status;


    if (healthy)
    {
        parcel_status = NUVO_PR_PARCEL_HEALTHY;
    }
    else
    {
        parcel_status = NUVO_PR_PARCEL_UNAVAILABLE;
    }

    parcel_info = nuvo_dlist_get_head_object(&cconn->open_parcel_list,
                                             struct nuvo_pr_parcel_info,
                                             list_node);
    while (parcel_info)
    {
        if (nuvo_pr->cm_info.vol_parcel_notify != NULL)
        {
            ret = nuvo_pr->cm_info.vol_parcel_notify(parcel_info->vol_uuid,
                                                     parcel_info->parcel_uuid,
                                                     parcel_status);
            if (ret < 0)
            {
                NUVO_ERROR_PRINT("Unable to update parcel health. Volume: " NUVO_LOG_UUID_FMT " Parcel: " NUVO_LOG_UUID_FMT " Error: %d",
                                 NUVO_LOG_UUID(parcel_info->vol_uuid),
                                 NUVO_LOG_UUID(parcel_info->parcel_uuid),
                                 ret);
                // If we can't find the parcel or volume, it's state
                // doesn't mean much.  Keep updating other parcels.
            }
        }

        parcel_info = nuvo_dlist_get_next_object(&cconn->open_parcel_list,
                                                 parcel_info,
                                                 struct nuvo_pr_parcel_info,
                                                 list_node);
    }
}

nuvo_return_t nuvo_pr_cconn_resend_opens(struct nuvo_pr_client_conn *cconn)
{
    struct nuvo_pr_parcel_info *parcel_info;

    nuvo_mutex_t sync_signal;

    if (nuvo_mutex_init(&sync_signal) != 0)
    {
        return (-NUVO_ENOMEM);
    }

    parcel_info = nuvo_dlist_remove_head_object(&cconn->open_parcel_list,
                                                struct nuvo_pr_parcel_info,
                                                list_node);

    // Move the open parcels to the reopen list. When a parcel open completes,
    // it will be moved back to the open parcel list.
    while (parcel_info)
    {
        nuvo_dlist_insert_tail(&cconn->reopen_parcel_list,
                               &parcel_info->list_node);
        parcel_info = nuvo_dlist_remove_head_object(&cconn->open_parcel_list,
                                                    struct nuvo_pr_parcel_info,
                                                    list_node);
    }

    parcel_info = nuvo_dlist_get_head_object(&cconn->reopen_parcel_list,
                                             struct nuvo_pr_parcel_info,
                                             list_node);

    while (parcel_info)
    {
        struct nuvo_dlist       submit_list;
        struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(
            &sync_signal);

        nuvo_dlist_init(&submit_list);
        nuvo_dlist_insert_tail(&submit_list, &req->list_node);

        // fill in the open the parcel request
        req->operation = NUVO_OP_OPEN;
        uuid_copy(req->open.parcel_uuid, parcel_info->parcel_uuid);
        uuid_copy(req->open.device_uuid, parcel_info->device_uuid);
        uuid_copy(req->open.volume_uuid, parcel_info->vol_uuid);
        req->open.reopen_flag = 1;
        req->open.reopen_pi = parcel_info;
        req->callback = nuvo_pr_reopen_complete_callback;

        parcel_info = nuvo_dlist_get_next_object(&cconn->reopen_parcel_list,
                                                 parcel_info,
                                                 struct nuvo_pr_parcel_info,
                                                 list_node);
        nuvo_mutex_unlock(&cconn->cc_mutex);
        NUVO_LOG(pr, 50, "Parcel reopen started, conn: %d , parcel_desc: %d",
                 GET_PR_CCONN_IDX(cconn), req->open.reopen_pi->parcel_desc);
        nuvo_pr_submit(&submit_list);
        nuvo_mutex_lock(&cconn->cc_mutex);
    }

    return (0);
}

void nuvo_pr_reopen_complete_callback(struct nuvo_io_request *req)
{
    ssize_t ret = 0;
    struct nuvo_pr_parcel_info *parcel_info;
    union parcel_descriptor     pdesc;
    struct nuvo_pr_pdef         pdef;
    uint32_t node_index;
    struct nuvo_pr_node_desc   *node_desc;
    struct nuvo_pr_client_conn *conn = NULL;

    NUVO_ASSERT(req->open.reopen_flag > 0);

    pdesc.pd = req->open.parcel_desc;
    NUVO_LOG(pr, 50, "Parcel reopen complete callback start, parcel_desc: %d",
             pdesc.pd);

    pdef = atomic_load(req->open.client_pdef);
    node_index = pdef.node_index;

    // TODO: If a device relocates to the local node, we need to do extra
    // work to handle this (maybe a "conn" for a local node?).
    NUVO_ASSERT(node_index != NUVO_PR_LOCAL_NODE_INDEX);

    node_desc = &nuvo_pr->node_table[node_index];
    nuvo_mutex_lock(&node_desc->nd_mutex);
    ret = nuvo_pr_get_conn(node_desc, &conn, false);
    nuvo_mutex_unlock(&node_desc->nd_mutex);

    if (ret < 0)
    {
        NUVO_ERROR_PRINT("Parcel reopen completion could not get conn %d .",
                         GET_PR_CCONN_IDX(conn));
        nuvo_pr_client_req_free(req);
        NUVO_ASSERT(!"Parcel reopen completed, but connection not found.");
        return;
    }

    if (req->status < 0)
    {
        NUVO_ERROR_PRINT(
            "Parcel reopen error encountered, parcel_desc: %d, error: %d",
            pdesc.pd, req->status);
        nuvo_pr_cconn_set_state(conn, NUVO_CCCS_ERROR);
    }

    if (conn->cc_state != NUVO_CCCS_RESENDING)
    {
        NUVO_ERROR_PRINT(
            "Parcel reopen completion - conn %d state is %d, parcel reopen will be resent when connection is healthy.",
            GET_PR_CCONN_IDX(conn), conn->cc_state);
        // Connection may have hit another error, so this req will be resent
        // during the next recovery phase.
        nuvo_mutex_unlock(&conn->cc_mutex);
        nuvo_pr_client_req_free(req);
        return;
    }

    parcel_info = req->open.reopen_pi;

    NUVO_ASSERT(pdesc.pd == parcel_info->parcel_desc);

    // The open succeeded, move the parcel back to the open list
    nuvo_dlist_remove(&parcel_info->list_node);
    nuvo_dlist_insert_tail(&conn->open_parcel_list, &parcel_info->list_node);

    NUVO_LOG(pr, 50,
             "Parcel reopen callback completed successfully, conn %d parcel_desc: %d",
             GET_PR_CCONN_IDX(conn), parcel_info->parcel_desc);

    // If this is the last completion, and let the conn mgr know we're done.
    parcel_info = nuvo_dlist_get_head_object(&conn->reopen_parcel_list,
                                             struct nuvo_pr_parcel_info,
                                             list_node);
    if (!parcel_info)
    {
        NUVO_LOG(pr, 50, "Last parcel reopen completed, parcel_desc: %d",
                 pdesc.pd);

        // Start the next phase of recovery.
        nuvo_pr_cconn_set_state(conn, NUVO_CCCS_RESEND_READY);
        conn->cc_resend_phase = NUVO_RESEND_DATA;
    }

    nuvo_mutex_unlock(&conn->cc_mutex);
    nuvo_pr_client_req_free(req);
}

void nuvo_pr_kontroller_config_done(bool is_done)
{
    if (is_done)
    {
        nuvo_pr_enable(true);
    }
    else
    {
        // A debug trigger is clearing node_init_done
        nuvo_pr->node_init_done = is_done;
    }
}

void nuvo_pr_idempotent_status_set(struct nuvo_io_request *req)
{
    switch (req->operation)
    {
    case NUVO_OP_READ:
    case NUVO_OP_READ_VERIFY:
    case NUVO_OP_WRITE:
        // No idempotent translation necessary
        return;

    case NUVO_OP_ALLOC:
        if (req->status == -NUVO_E_PARCEL_ALREADY_ALLOC)
        {
            req->status = 0;
            req->idempotent_status_flag = 1;
        }
        break;

    case NUVO_OP_OPEN:
        if (req->status == -NUVO_E_PARCEL_ALREADY_OPEN)
        {
            req->status = 0;
            req->idempotent_status_flag = 1;
        }
        break;

    case NUVO_OP_CLOSE:
        if (req->status == -NUVO_E_PARCEL_ALREADY_CLOSED)
        {
            req->status = 0;
            req->idempotent_status_flag = 1;
        }
        break;

    case NUVO_OP_FREE:
        if (req->status == -NUVO_E_PARCEL_ALREADY_FREE)
        {
            req->status = 0;
            req->idempotent_status_flag = 1;
        }
        break;

    default:
        return;
    }

    if (req->idempotent_status_flag)
    {
        NUVO_LOG(pr, 0, "Translated idempotent operation %d status to success.",
                 req->operation);
    }
}

void nuvo_pr_log_stats(void)
{
    struct nuvo_pr_client_conn *cconn;
    struct nuvo_pr_client_conn *cconn_next;
    struct nuvo_pr_server_conn *sconn;
    struct nuvo_pr_server_conn *sconn_next;


    NUVO_LOG(pr, 0, "Client stats for the PR:");
    NUVO_LOG(pr, 0, "Client connection active list:");
    nuvo_mutex_lock(&nuvo_pr->client_conn_mutex);
    cconn = nuvo_dlist_get_head_object(&nuvo_pr->client_conn_active_list,
                                       struct nuvo_pr_client_conn, list_node);
    while (cconn != NULL)
    {
        cconn_next = nuvo_dlist_get_next_object(
            &nuvo_pr->client_conn_active_list, cconn,
            struct nuvo_pr_client_conn, list_node);
        nuvo_mutex_unlock(&nuvo_pr->client_conn_mutex);
        nuvo_mutex_lock(&cconn->cc_mutex);

        nuvo_pr_log_cconn_queues(cconn);

        nuvo_mutex_lock(&nuvo_pr->client_conn_mutex);
        nuvo_mutex_unlock(&cconn->cc_mutex);

        cconn = nuvo_dlist_get_next_object(&nuvo_pr->client_conn_active_list,
                                           cconn, struct nuvo_pr_client_conn,
                                           list_node);
        if (cconn_next != cconn)
        {
            NUVO_LOG(pr, 0,
                     "Client connection active list modified during stats logging.  Restarting stats logging.");
            cconn = nuvo_dlist_get_head_object(
                &nuvo_pr->client_conn_active_list,
                struct nuvo_pr_client_conn, list_node);
        }
    }
    nuvo_mutex_unlock(&nuvo_pr->client_conn_mutex);

    NUVO_LOG(pr, 0, "Client connection error list:");
    nuvo_mutex_lock(&nuvo_pr->client_conn_mutex);
    cconn = nuvo_dlist_get_head_object(&nuvo_pr->client_conn_error_list,
                                       struct nuvo_pr_client_conn, list_node);
    while (cconn != NULL)
    {
        cconn_next = nuvo_dlist_get_next_object(
            &nuvo_pr->client_conn_error_list, cconn,
            struct nuvo_pr_client_conn, list_node);
        nuvo_mutex_unlock(&nuvo_pr->client_conn_mutex);
        nuvo_mutex_lock(&cconn->cc_mutex);

        nuvo_pr_log_cconn_queues(cconn);

        nuvo_mutex_lock(&nuvo_pr->client_conn_mutex);
        nuvo_mutex_unlock(&cconn->cc_mutex);

        cconn = nuvo_dlist_get_next_object(&nuvo_pr->client_conn_error_list,
                                           cconn, struct nuvo_pr_client_conn,
                                           list_node);
        if (cconn_next != cconn)
        {
            NUVO_LOG(pr, 0,
                     "Client connection error list modified during stats logging.  Restarting stats logging.");
            cconn = nuvo_dlist_get_head_object(&nuvo_pr->client_conn_error_list,
                                               struct nuvo_pr_client_conn,
                                               list_node);
        }
    }
    nuvo_mutex_unlock(&nuvo_pr->client_conn_mutex);

    NUVO_LOG(pr, 0, "Server stats for the PR:");
    NUVO_LOG(pr, 0, "Server connection active list:");
    nuvo_mutex_lock(&nuvo_pr->server_conn_mutex);
    sconn = nuvo_dlist_get_head_object(&nuvo_pr->server_conn_active_list,
                                       struct nuvo_pr_server_conn, list_node);
    while (sconn != NULL)
    {
        sconn_next = nuvo_dlist_get_next_object(
            &nuvo_pr->server_conn_active_list,
            sconn, struct nuvo_pr_server_conn,
            list_node);
        nuvo_mutex_unlock(&nuvo_pr->server_conn_mutex);
        nuvo_mutex_lock(&sconn->sc_mutex);

        nuvo_pr_log_sconn_queues(sconn);

        nuvo_mutex_lock(&nuvo_pr->server_conn_mutex);
        nuvo_mutex_unlock(&sconn->sc_mutex);

        sconn = nuvo_dlist_get_next_object(&nuvo_pr->server_conn_active_list,
                                           sconn, struct nuvo_pr_server_conn,
                                           list_node);
        if (sconn_next != sconn)
        {
            NUVO_LOG(pr, 0,
                     "Server connection active list modified during stats logging.  Restarting stats logging.");
            sconn = nuvo_dlist_get_head_object(
                &nuvo_pr->server_conn_active_list,
                struct nuvo_pr_server_conn, list_node);
        }
    }
    nuvo_mutex_unlock(&nuvo_pr->server_conn_mutex);

    nuvo_pr_print_req_buf_stats();
}

void nuvo_pr_log_cconn_queues(struct nuvo_pr_client_conn *cconn)
{
    struct nuvo_io_request *req;

    // Print client connection stats
    NUVO_LOG(pr, 0, "Client conn %d: state: %d gen: %d socket: %d",
             GET_PR_CCONN_IDX(cconn), cconn->cc_state, cconn->cc_gen,
             cconn->sock_fd);
    NUVO_LOG(pr, 0, "Client conn %d: send_bytes: %lu recv_bytes: %lu",
             GET_PR_CCONN_IDX(cconn), cconn->send_total_bytes,
             cconn->recv_total_bytes);
    NUVO_LOG(pr, 0,
             "Client conn %d: conn_err_cnt: %d prev_close_err: %d prev_close_reason: %d",
             GET_PR_CCONN_IDX(cconn), cconn->conn_err_cnt,
             cconn->prev_close_err, cconn->prev_close_reason);
    NUVO_LOG(pr, 0, "Client conn %d: send_req: %p recv_req: %p",
             GET_PR_CCONN_IDX(cconn), (void *)cconn->send_req,
             (void *)cconn->recv_req);

    // Print lists: req_pending_list, req_wait_list, req_retry_list
    NUVO_LOG(pr, 0, "Client conn %d: Request pending list:",
             GET_PR_CCONN_IDX(cconn));
    req = nuvo_dlist_get_head_object(&cconn->req_pending_list,
                                     struct nuvo_io_request, list_node);
    while (req != NULL)
    {
        NUVO_LOG(pr, 0, "Request %p: op: %d status: %d attempt: %d",
                 (void *)req, req->operation, req->status, req->op_retry_cnt);

        req = nuvo_dlist_get_next_object(&cconn->req_pending_list, req,
                                         struct nuvo_io_request, list_node);
    }

    NUVO_LOG(pr, 0, "Client conn %d: Request retry list:",
             GET_PR_CCONN_IDX(cconn));
    req = nuvo_dlist_get_head_object(&cconn->req_retry_list,
                                     struct nuvo_io_request, list_node);
    while (req != NULL)
    {
        NUVO_LOG(pr, 0, "Request %p: op: %d status: %d attempt: %d",
                 (void *)req, req->operation, req->status, req->op_retry_cnt);

        req = nuvo_dlist_get_next_object(&cconn->req_retry_list, req,
                                         struct nuvo_io_request, list_node);
    }

    NUVO_LOG(pr, 0, "Client conn %d: Request wait list:",
             GET_PR_CCONN_IDX(cconn));
    req = nuvo_dlist_get_head_object(&cconn->req_wait_list,
                                     struct nuvo_io_request, list_node);
    while (req != NULL)
    {
        NUVO_LOG(pr, 0, "Request %p: op: %d status: %d attempt: %d",
                 (void *)req, req->operation, req->status, req->op_retry_cnt);

        req = nuvo_dlist_get_next_object(&cconn->req_wait_list, req,
                                         struct nuvo_io_request, list_node);
    }
}

void nuvo_pr_log_sconn_queues(struct nuvo_pr_server_conn *sconn)
{
    struct nuvo_io_request *req;

    NUVO_LOG(pr, 0, "Server conn %d: state: %d gen: %d socket: %d",
             GET_PR_SCONN_IDX(sconn), sconn->sc_state, sconn->sc_gen,
             sconn->sock_fd);
    NUVO_LOG(pr, 0, "Server conn %d: send bytes: %lu recv bytes: %lu",
             GET_PR_SCONN_IDX(sconn), sconn->send_total_bytes,
             sconn->recv_total_bytes);
    NUVO_LOG(pr, 0, "Server conn %d: send_req: %p recv_req: %p",
             GET_PR_SCONN_IDX(sconn), (void *)sconn->send_req,
             (void *)sconn->recv_req);

    NUVO_LOG(pr, 0, "Server conn %d: Request ready list:",
             GET_PR_SCONN_IDX(sconn));
    req = nuvo_dlist_get_head_object(&sconn->req_ready_list,
                                     struct nuvo_io_request, list_node);
    while (req != NULL)
    {
        NUVO_LOG(pr, 0, "Request %p: op: %d status: %d attempt: %d",
                 (void *)req, req->operation, req->status, req->op_retry_cnt);

        req = nuvo_dlist_get_next_object(&sconn->req_ready_list, req,
                                         struct nuvo_io_request, list_node);
    }
}

bool nuvo_pr_fi_idempotent_error(struct nuvo_io_request *req)
{
    int64_t  l_errno = 0;
    uint32_t idempotent_retry_max = 1;

    // Check if fault injection is set for all parcel config ops.
    switch (req->operation)
    {
    case NUVO_OP_READ:
    case NUVO_OP_READ_VERIFY:
    case NUVO_OP_WRITE:
    case NUVO_OP_DEV_INFO:
        return (false);

    case NUVO_OP_ALLOC:
        return (false); // When idempotent alloc supported, remove this line.

    case NUVO_OP_OPEN:
    case NUVO_OP_CLOSE:
    case NUVO_OP_FREE:
        // Once we've retried the op a few times, let the op succeed
        // Also, don't set errors on config resend requests, because they
        // are recreated on connection failure (with a retry_cnt of 0).
        if ((req->op_retry_cnt >= idempotent_retry_max) ||
            (nuvo_pr_is_resend_config_req(req)))
        {
            return (false);
        }

        if (test_fi_inject_rc(TEST_FI_PR_SERVER_SEND_ALL_CONFIG,
                              nuvo_pr->pr_test_info, &l_errno))
        {
            return (true);
        }
        break;

    default:
        return (false);
    }

    // Check if fault injection is set for individual parcel config ops.
    switch (req->operation)
    {
    case NUVO_OP_ALLOC:
        if (test_fi_inject_rc(TEST_FI_PR_SERVER_SEND_ALLOC,
                              nuvo_pr->pr_test_info, &l_errno))
        {
            return (true);
        }
        break;

    case NUVO_OP_OPEN:
        if (test_fi_inject_rc(TEST_FI_PR_SERVER_SEND_OPEN,
                              nuvo_pr->pr_test_info, &l_errno))
        {
            return (true);
        }
        break;

    case NUVO_OP_CLOSE:
        if (test_fi_inject_rc(TEST_FI_PR_SERVER_SEND_CLOSE,
                              nuvo_pr->pr_test_info, &l_errno))
        {
            return (true);
        }
        if (test_fi_inject_rc(TEST_FI_PR_SERVER_SEND_CLOSE_FREE,
                              nuvo_pr->pr_test_info, &l_errno))
        {
            return (true);
        }

        break;

    case NUVO_OP_FREE:
        if (test_fi_inject_rc(TEST_FI_PR_SERVER_SEND_FREE,
                              nuvo_pr->pr_test_info, &l_errno))
        {
            return (true);
        }
        if (test_fi_inject_rc(TEST_FI_PR_SERVER_SEND_CLOSE_FREE,
                              nuvo_pr->pr_test_info, &l_errno))
        {
            return (true);
        }
        break;

    default:
        return (false);
    }

    return (false);
}

struct test_fi_info *nuvo_pr_get_test_fi(void)
{
    if (nuvo_pr->pr_test_info == NULL)
    {
        nuvo_pr->pr_test_info = malloc(sizeof(struct test_fi_info));
        if (nuvo_pr->pr_test_info == NULL)
        {
            NUVO_ERROR_PRINT(
                "Fault Injection: Failed to set pr trigger due to mem alloc fail");
            return (NULL);
        }
        memset(nuvo_pr->pr_test_info, 0, sizeof(*nuvo_pr->pr_test_info));
    }

    return (nuvo_pr->pr_test_info);
}
