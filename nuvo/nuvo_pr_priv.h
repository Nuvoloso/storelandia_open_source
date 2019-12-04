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

/**
 * @file nuvo_pr_priv.h
 * @brief Definitions for the private interface for the parcel router
 */

#pragma once

#include <netinet/in.h>

#include "status.h"
#include "nuvo_pr.h"
#include "nuvo_lock.h"
#include "fault_inject.h"
#include "device_type.h"

/** The maximum length of a node's address, not including the null terminator. */
#define NUVO_MAX_ADDR_LEN                  (63)

/** The maximum number of buffers available in our buffer pool. */
#define NUVO_PR_MAX_BUFS                   (NUVO_BUF_MEM / NUVO_BLOCK_SIZE)

/** The maximum number of device records we support per node. */
#define NUVO_PR_MAX_DEVS                   (8 * 1024)
/** The number of bits needed to store an index to a struct nuvo_pr_node_desc in the nuvo_pr pool. */
#define NUVO_PR_MAX_NODES_BITS             (12)
/** The maximum number of nodes we support */
#define NUVO_PR_MAX_NODES                  ((1ull << NUVO_PR_MAX_NODES_BITS) - 1ull)
/** A reserved node index value that represents an invalid node. */
#define NUVO_PR_NODE_INVALID               (NUVO_PR_MAX_NODES)
/** The number of bits needed to store an index to a struct nuvo_pr_pdef in the nuvo_pr pool. */
#define NUVO_PR_MAX_PDS_BITS               (20)
/** The maximum number of parcel definitions we support. */
#define NUVO_PR_MAX_PDS                    (1ull << NUVO_PR_MAX_PDS_BITS)
/** The number of bits needed to store an index to a struct nuvo_io_request in the nuvo_pr pool. */
#define NUVO_PR_MAX_REQS_BITS              (11)
/** The maximum number of struct nuvo_io_requests we support in our nuvo_pr pool. */
#define NUVO_PR_MAX_REQS                   ((1ull << NUVO_PR_MAX_REQS_BITS) - 1ull)

/** The index of the struct nuvo_pr_node_desc in the nuvo_pr pool describing the local node. */
#define NUVO_PR_LOCAL_NODE_INDEX           (0)

/** The maximum number of events to retrieve for each call of epoll_wait. */
#define NUVO_PR_EPOLL_EVENTS               (256)

/** The maximum number of backlogged connect requests on our listener socket. */
#define NUVO_SERVER_BACKLOG                (50)

/** A reserved value used to indicate an invalid value in 32bit fields.  */
#define NUVO_PR_INVALID32                  (~(uint32_t)0)

/** The number of bits used to store the gen in union parcel_descriptor. */
#define NUVO_PR_PD_GEN_BITS                (CHAR_BIT * sizeof(uint_fast32_t) - NUVO_PR_MAX_PDS_BITS)

/** The number of times we will attempt to reconnect before giving up. */
#define NUVO_PR_MAX_CONN_RETRIES           (20)

/**
 * The minimum time in seconds that we wait before attempting to recover
 * a connection that already failed recovery.
 */
#define NUVO_PR_CONN_MIN_RETRY_SECS        (1)

/**
 * The maximum time in seconds that we wait before attempting to recover
 * a connection that already failed recovery.
 */
#define NUVO_PR_CONN_MAX_RETRY_SECS        (60)

/**
 * The number of seconds we wait before starting recovery attempt backoff.
 * This means we will retry every second for the first minute after a failure.
 */
#define NUVO_PR_CONN_BACKOFF_WAIT_SECS     (60)

/**
 * The number of additional seconds we backoff after every failed recovery
 * attempt.  We keep backing off until we hit NUVO_PR_CONN_BACKOFF_DELAY_SECS.
 */
#define NUVO_PR_CONN_BACKOFF_EXTRA_SECS    (5)

/** How many seconds we attempt to shutdown before we give up (and ASSERT). */
#define NUVO_PR_CONN_SHUTDOWN_MAX_SECS     (300)

/**
 * The time in ms that epoll will wait during socket recovery.  When the
 * timeout is hit, conn_mgr will continue recovery and may epoll again.
 */
#define NUVO_PR_RECOVERY_EPOLL_WAIT        (250)

/**
 * \brief A union used to format a parcel descriptor.
 *
 * Parcel descriptors returned by the parcel router layer are of this format.
 * the index field is used to index into the struct nuvo_pr_pdef pool at
 * nuvo_pr->pdef_table, and the gen must match the gen field of the struct
 * nuvo_pr_pdef at the index.  When parcel descriptors are closed, the parcel
 * router layer increments the gen field of the corresponding pdef.  This
 * makes old parcel descriptors have an inconsistent gen value and thus
 * invalidates them.
 *
 * \sa nuvo_pr_pdef, nuvo_pr_pdef_to_pdesc, nuvo_pr_pdef_get, nuvo_pr_pdef_add_outstanding
 */
union parcel_descriptor
{
    uint_fast32_t pd;
    struct {
        uint_fast32_t index : NUVO_PR_MAX_PDS_BITS;
        uint_fast32_t gen   : NUVO_PR_PD_GEN_BITS;
    };
};

/** The number of bits used to store the gen in union nuvo_pr_pdef. */
#define NUVO_PR_PDEF_GEN_BITS    (32 - NUVO_PR_MAX_NODES_BITS - NUVO_PR_MAX_REQS_BITS)

/**
 * \brief A structure to store information about open parcels.
 *
 * The parcel router must route requests between many nodes.  As such, it
 * must translate parcel descriptors as a client may want to open a native
 * parcel and remove parcel that each have the same parcel descriptor on their
 * respective nodes.  Thus the parcel router layer has a translation table of
 * nuvo_pr_pdef structures that are referenced by the parcel descriptors the
 * parcel router outputs, and allows the parcel router to map to native parcel
 * descriptors on other nodes.  Each of these pdefs stores the value of the
 * node which the parcel is native to, and what the parcel descriptor for that
 * parcel is on the native node.  The parcel router layer then generates a
 * parcel descriptor that refers to these pdefs.  Since there are only a
 * limited number of pdefs in the pool, they can end up being reused.  To avoid
 * an old parcel_descriptor incorrectly referring to a reused nuvo_pr_pdef,
 * each pdef has a gen that is also stored inside each pdesc.  When a pdef is
 * reused, the gen is incremented.  This makes previous pdescs referring to
 * the pdef inconsistent.  Additionally, the parcel router layer also keeps
 * track of the number of oustanding operations for a given pdef in the
 * outstanding_io field.
 *
 * \sa parcel_descriptor, nuvo_pr_pdef_alloc, nuvo_pr_pdef_free, nuvo_pr_pdef_get, nuvo_pr_pdef
 */
struct nuvo_pr_pdef {
    union
    {
        uint32_t native_pd;
        uint32_t next_pdef_index;
    };
    uint32_t node_index     : NUVO_PR_MAX_NODES_BITS;
    uint32_t outstanding_io : NUVO_PR_MAX_REQS_BITS;
    uint32_t gen            : NUVO_PR_PDEF_GEN_BITS;
};

static_assert(NUVO_PR_PD_GEN_BITS >= NUVO_PR_PDEF_GEN_BITS, "Parcel descriptor must have more or an equal amount of gen bits than the parcel definition.");

static_assert(sizeof(struct nuvo_pr_pdef) == 8, "Size of struct nuvo_pr_pdef is incorrect.");


/**
 * \brief A structure to store relevant uuids for opened parcels.
 *
 * Each connection has a list of the currently open parcels for the
 * given node.  In the event of a failure, it will use this to recreate
 * the state and remap entries in the more frequently used pdef table.
 */
struct nuvo_pr_parcel_info {
    uint32_t           parcel_desc;
    uuid_t             parcel_uuid;
    uuid_t             device_uuid;
    uuid_t             vol_uuid;
    struct nuvo_dlnode list_node;
};

/**
 * \brief The client connection state.
 * NUVO_CCCS_CLOSED - The initial state of a connection
 * NUVO_CCCS_CONNECTING - Waiting for socket to be ready, ops can be queued
 * NUVO_CCCS_CONNECTED - Healthy connection state
 * NUVO_CCCS_ERROR - Error occurred, conn_mgr will start recovery
 * NUVO_CCCS_RECONNECT - close/open socket, put socket on epoll and wait
 * NUVO_CCCS_RESEND_READY - epoll notification socket is healthy, start sending
 * NUVO_CCCS_RESENDING - resend ops in flight at time of error
 *
 */
enum nuvo_cconn_cstate
{
    NUVO_CCCS_CLOSED = 0,
    NUVO_CCCS_CONNECTING,
    NUVO_CCCS_CONNECTED,
    NUVO_CCCS_ERROR,
    NUVO_CCCS_RECONNECT,
    NUVO_CCCS_RESEND_READY,
    NUVO_CCCS_RESENDING
};

#define NUVO_PR_IS_CCONN_IN_RECOVERY(cconn)        \
    ((conn)->cc_state == NUVO_CCCS_RECONNECT ||    \
     (conn)->cc_state == NUVO_CCCS_RESEND_READY || \
     (conn)->cc_state == NUVO_CCCS_RESENDING)


/**
 * \brief Phases tied to the RESEND_READY and RESENDING connection states.
 *
 * While reconnecting, the local node will resend both configuration
 * and data ops.  Rather than add two more states, there are two phases
 * representing the config and data resend.  If config operations other
 * than parcel opens need to be added, they can be added to the phases
 * instead of introducing more connection states.
 *
 * NUVO_RESEND_NONE   - Resend phase is not active
 * NUVO_RESEND_CONFIG - The initial state of a connection
 * NUVO_RESEND_DATA   - Waiting for socket to be ready, ops can be queued
 */
enum nuvo_cconn_resend_phase
{
    NUVO_RESEND_NONE   = 0,
    NUVO_RESEND_CONFIG = 1,
    NUVO_RESEND_DATA   = 2
};

enum nuvo_cconn_sstate
{
    NUVO_CCSS_IDLE = 0,
    NUVO_CCSS_HEADER,
    NUVO_CCSS_HASHESDATA
};

enum nuvo_cconn_rstate
{
    NUVO_CCRS_HEADER = 0,
    NUVO_CCRS_HASHESDATA
};

enum nuvo_sconn_cstate
{
    NUVO_SCCS_CLOSED = 0,
    NUVO_SCCS_CONNECTED,
    NUVO_SCCS_CLOSING,
    NUVO_SCCS_ERROR
};

enum nuvo_sconn_sstate
{
    NUVO_SCSS_IDLE = 0,
    NUVO_SCSS_HEADER,
    NUVO_SCSS_HASHESDATA
};

enum nuvo_sconn_rstate
{
    NUVO_SCRS_WAIT = 0,
    NUVO_SCRS_HEADER,
    NUVO_SCRS_HASHESDATA
};

/**
 * An enum which describes why/what triggered the connection to be closed.
 * For example, an EPOLL failed or a SEND failed.
 */
enum nuvo_conn_close_reason
{
    NUVO_CCR_NONE = 0,
    NUVO_CCR_NORMAL,
    NUVO_CCR_NODE_REMOVE,
    NUVO_CCR_EPOLL,
    NUVO_CCR_SEND,
    NUVO_CCR_WRITEV,
    NUVO_CCR_RECV,
    NUVO_CCR_RECV_NO_DATA,
    NUVO_CCR_HEADER_HASH,
    NUVO_CCR_HEADER_TAG,
    NUVO_CCR_READV,
    NUVO_CCR_READV_NO_DATA,
    NUVO_CCR_DATA_HASH
};

/** A union representing the tag format used for network requests. */
union nuvo_net_tag
{
    uint64_t uint64;
    struct {
        uint64_t req_index  : NUVO_PR_MAX_REQS_BITS;
        uint64_t conn_index : NUVO_PR_MAX_NODES_BITS;
        uint64_t node_index : NUVO_PR_MAX_NODES_BITS;
    };
};

/** A structure representing the format of network request headers. */
struct __attribute__ ((packed)) nuvo_net_req_header {
    union nuvo_net_tag tag;
    uint32_t           operation;
    uint32_t           op_retry_cnt; // Can steal bits from here for flags

    union __attribute__ ((packed))
    {
        struct __attribute__ ((packed)) {
            uint32_t            parcel_desc;
            uint32_t            block_offset;
            uint32_t            block_count;
            enum nuvo_io_origin io_origin;
        } rw;
        struct __attribute__ ((packed)) {
            uuid_t parcel_uuid;
            uuid_t device_uuid;
            uuid_t volume_uuid;
        } open;
        struct __attribute__ ((packed)) {
            uint32_t parcel_desc;
        } close;
        struct __attribute__ ((packed)) {
            uuid_t parcel_uuid;
            uuid_t device_uuid;
            uuid_t volume_uuid;
        } alloc;
        struct __attribute__ ((packed)) {
            uuid_t parcel_uuid;
            uuid_t device_uuid;
            uuid_t volume_uuid;
        } free;
        struct __attribute__ ((packed)) {
            uuid_t device_uuid;
        } dev_info;
        uint8_t pad[104];
    };

    nuvo_hash_t hash;
};
static_assert(sizeof(struct nuvo_net_req_header) == 128, "struct nuvo_net_req_header has incorrect size.");


/** A structure representing the format of network response headers. */
struct __attribute__ ((packed)) nuvo_net_resp_header {
    union nuvo_net_tag tag;
    int64_t            status;

    union __attribute__ ((packed))
    {
        struct __attribute__ ((packed)) {
            uint32_t parcel_desc;
        } open;
        struct __attribute__ ((packed)) {
            uuid_t parcel_uuid;
        } alloc;
        struct __attribute__ ((packed)) {
            uint64_t           device_size;
            uint64_t           parcel_size;
            enum nuvo_dev_type device_type;
        } dev_info;
        uint8_t pad[40];
    };

    nuvo_hash_t hash;
};
static_assert(sizeof(struct nuvo_net_resp_header) == 64, "struct nuvo_net_resp_header has incorrect size.");


/** A union describing the format of the tag used for epoll events. */
union nuvo_pr_event_tag
{
    uint64_t u64;
    struct {
        uint32_t conn_index;
        uint32_t conn_gen;
    };
};

/** A structure for the client/server connection manager */
struct nuvo_pr_conn_mgr {
    nuvo_mutex_t  cm_work_mutex;
    nuvo_cond_t   cm_work_cv;

    int           recovery_epoll_fd;
    uint32_t      conn_recovery_cnt;
    // Notify volume of parcel availability, without including vol headers.
    nuvo_return_t (*vol_parcel_notify)(const uuid_t, uuid_t,
                                       enum nuvo_pr_parcel_status);
};

/** A structure to describe the state of a client side network connection */
struct nuvo_pr_client_conn {
    nuvo_mutex_t                 cc_mutex;
    uint_fast32_t                cc_gen;
    enum nuvo_cconn_cstate       cc_state;
    enum nuvo_cconn_resend_phase cc_resend_phase;
    int                          sock_fd;
    struct nuvo_pr_node_desc    *node_desc;
    struct nuvo_dlist            req_wait_list;
    struct nuvo_dlist            req_pending_list;
    struct nuvo_dlist            req_retry_list;
    uint_fast32_t                req_outstanding; // Currently not used

    enum nuvo_conn_close_reason  prev_close_reason;
    int64_t                      prev_close_err;
    int64_t                      conn_err_cnt;
    uint64_t                     recovery_start_ts;
    uint32_t                     backoff_cnt;
    struct nuvo_dlist            open_parcel_list;
    struct nuvo_dlist            reopen_parcel_list;

    struct nuvo_io_request      *send_req;
    struct nuvo_net_req_header   send_header;
    enum nuvo_cconn_sstate       send_state;
    uint_fast32_t                send_count;
    uint_fast64_t                send_total_bytes;

    struct nuvo_io_request      *recv_req;
    struct nuvo_net_resp_header  recv_header;
    enum nuvo_cconn_rstate       recv_state;
    uint_fast32_t                recv_count;
    uint_fast64_t                recv_total_bytes;

    struct nuvo_dlnode           list_node;
};

/** A structure to decribe the state of a server side network connection */
struct nuvo_pr_server_conn {
    nuvo_mutex_t                sc_mutex;
    uint_fast32_t               sc_gen;
    enum nuvo_sconn_cstate      sc_state;
    int                         sock_fd;
    struct nuvo_dlist           req_ready_list;
    uint_fast32_t               req_outstanding;

    enum nuvo_conn_close_reason prev_close_reason;
    int64_t                     prev_close_err;
    uint32_t                    shutdown_start_ts;

    struct nuvo_io_request     *send_req;
    struct nuvo_net_resp_header send_header;
    enum nuvo_sconn_sstate      send_state;
    uint_fast32_t               send_count;
    uint_fast64_t               send_total_bytes;

    struct nuvo_io_request     *recv_req;
    struct nuvo_net_req_header  recv_header;
    enum nuvo_sconn_rstate      recv_state;
    uint_fast32_t               recv_count;
    uint_fast64_t               recv_total_bytes;

    union
    {
        struct nuvo_pr_req_alloc req_alloc;
        struct nuvo_pr_buf_alloc buf_alloc;
    };

    struct nuvo_dlnode          list_node;
};

/** A structure used for storing device to node records. */
struct nuvo_pr_device_desc {
    uuid_t        id;
    uint_fast16_t node_index;
};

/** A structure used for storing node records. */
struct nuvo_pr_node_desc {
    nuvo_mutex_t                nd_mutex;
    uuid_t                      id;
    struct nuvo_pr_client_conn *conn;
    struct nuvo_lnode           list_next;
    uint_fast16_t               port;
    char                        address[NUVO_MAX_ADDR_LEN + 1];
};

struct nuvo_pr_req_pool {
    nuvo_mutex_t           req_mutex;
    struct nuvo_dlist      req_alloc_list;
    uint_fast32_t          req_max_used;
    struct nuvo_dlist      req_free_list;
    uint_fast32_t          req_free_cnt;
    struct nuvo_io_request req_table[NUVO_PR_MAX_REQS];
};

struct nuvo_pr_buf_pool {
    nuvo_mutex_t      buf_mutex;
    struct nuvo_dlist buf_alloc_list;
    uint_fast32_t     buf_max_used;
    struct nuvo_dlist buf_free_list;
    uint_fast32_t     buf_free_cnt;
    union __attribute__ ((aligned(NUVO_BLOCK_SIZE)))
    {
        struct nuvo_dlnode list_node;
        uint8_t            buf[NUVO_BLOCK_SIZE];
    }                           buf_table[NUVO_PR_MAX_BUFS];
};

/** The top level structure for all parcel router layer data. */
struct nuvo_parcel_router {
    uuid_t                      local_node_id;

    pthread_t                   conn_mgr_thread;
    struct nuvo_pr_conn_mgr     cm_info;

    pthread_t                   client_thread;
    int                         client_epoll_fd;

    pthread_t                   server_thread;
    int                         server_listen_sock;
    int                         server_epoll_fd;

    int                         shutdown_flag;

    int                         enabled;
    nuvo_mutex_t                enable_mutex;
    nuvo_cond_t                 enable_cv;
    bool                        node_init_done;

    nuvo_mutex_t                node_mutex;
    uint_fast32_t               node_used;
    struct nuvo_list            node_free_list;
    struct nuvo_pr_node_desc    node_table[NUVO_PR_MAX_NODES];

    nuvo_mutex_t                device_mutex;
    uint_fast32_t               device_count;
    struct nuvo_pr_device_desc  device_list[NUVO_PR_MAX_DEVS];

    nuvo_mutex_t                client_conn_mutex;
    uint_fast32_t               client_conn_used;
    struct nuvo_dlist           client_conn_free_list;
    struct nuvo_dlist           client_conn_active_list;
    struct nuvo_dlist           client_conn_error_list;
    struct nuvo_pr_client_conn  client_conn_table[NUVO_PR_MAX_NODES];

    nuvo_mutex_t                server_conn_mutex;
    uint_fast32_t               server_conn_used;
    struct nuvo_dlist           server_conn_free_list;
    struct nuvo_dlist           server_conn_active_list;
    struct nuvo_pr_server_conn  server_conn_table[NUVO_PR_MAX_NODES];

    struct nuvo_pr_req_pool     client_req_pool;
    struct nuvo_pr_req_pool     server_req_pool;

    nuvo_mutex_t                pdef_mutex;

    uint_fast32_t               pdef_used;
    uint_fast32_t               pdef_free_list;
    _Atomic struct nuvo_pr_pdef pdef_table[NUVO_PR_MAX_PDS];

    struct nuvo_pr_buf_pool     client_buf_pool;
    struct nuvo_pr_buf_pool     server_buf_pool;

    // Testing - Fault Injection
    struct test_fi_info        *pr_test_info;
};

extern struct nuvo_parcel_router *nuvo_pr;

/**
 * \brief Allocate a struct nuvo_pr_node_desc from the local pool.
 *
 * For parcel router internal use only.  Allocates a struct nuvo_pr_node_desc
 * from the local pool if available.  If there are none left, NULL will be
 * returned.
 *
 * \returns A pointer to a struct nuvo_pr_node_desc on success.  Otherwise
 * returns NULL on failure.
 *
 */
struct nuvo_pr_node_desc *nuvo_pr_node_alloc();

/**
 * \brief Free a struct nuvo_pr_node_desc.
 *
 * For parcel router internal use only.  Frees a struct nuvo_pr_node_desc that
 * was previously allocated via nuvo_pr_node_alloc().
 *
 */
void nuvo_pr_node_free(struct nuvo_pr_node_desc *node_desc);

/**
 * \brief Finds the index to a struct nuvo_pr_node_desc that matches the UUID.
 *
 * For parcel router internal use only.  This function searches the list of
 * struct nuvo_pr_node_desc in the parcel router layer for a struct
 * nuvo_pr_node_desc whose UUID matches \p node_id, and returns an index into
 * nuvo_pr->node_table.  The nuvo_pr->node_mutex be held before invoking the
 * function.
 *
 * \param node_id The UUID of the node to find.
 * \param index A pointer to an integer to return the index in.
 * \returns On success a zero or positive integer is returned.  On failure a
 * a negative integer is returned.
 * \retval -NUVO_ENOENT Node entry not found.
 */
nuvo_return_t nuvo_pr_node_find(const uuid_t node_id, uint_fast16_t *index);

/**
 * \brief Finds the index in the device list that a device UUID would be.
 *
 * For parcel router internal use only.  This function searches the device
 * list for the provided device UUID in \p dev_id.  An index to where the
 * device UUID would be is returned in the integer pointed to by \p index.
 * If a device record with a matching UUID exists in the list, it will be
 * located at the index.  If such a device does not exist in the list, the
 * index will point to where such a device should be inserted into the list.
 *
 * \param dev_id The UUID of the device to find.
 * \param index A pointer to an integer to return the index in.
 * \returns If a device is found, returns zero or a positive integer.  If no
 * device in the list matched the UUID, returns a negative integer.
 * \retval -NUVO_ENODEV Device not found.
 */
nuvo_return_t nuvo_pr_device_find(const uuid_t dev_id, uint_fast32_t *index);

/**
 * \brief Removes all device records associated with the struct
 * nuvo_pr_node_desc at index \p node_index.
 *
 * For parcel router internal use only.  This function removes all device
 * records associated with the struct nuvo_pr_node_desc at index \p node_index.
 *
 * \param node_index Index of the struct nuvo_pr_node_desc in the
 * nuvo_pr->node_table.
 * \returns Zero or a positive integer on success.  On failure, returns a
 * negative integer.
 */
nuvo_return_t nuvo_pr_device_remove_all_index(uint_fast16_t node_index);


/**
 * \brief Set the connection state, and assert invalid state transitions
 *
 * This function is for showing all the possible client connection state
 * transitions in one place. Assert if the state transition is not expected.
 *
 * \param conn The client connection to change state.
 * \param state The new state of the client connection.
 */
void nuvo_pr_cconn_set_state(struct nuvo_pr_client_conn *conn,
                             enum nuvo_cconn_cstate      state);

/**
 * \brief Allocate a struct nuvo_pr_client_conn.
 *
 * For parcel router internal use only.  This function allocates a struct
 * nuvo_pr_client_conn from the parcel router's pool.
 *
 * \returns Returns a pointer to a struct nuvo_pr_client_conn if successful.
 * If none are left in the pool, a NULL pointer is returned.
 */
struct nuvo_pr_client_conn *nuvo_pr_cconn_alloc();

/**
 * \brief Free a struct nuvo_pr_client_conn.
 *
 * For parcel router internal use only.  This function frees a struct
 * nuvo_pr_client_conn that was previously allocated by nuvo_pr_cconn_alloc.
 */
void nuvo_pr_cconn_free(struct nuvo_pr_client_conn *conn);

/**
 * \brief Enqueue a request to be sent over a client connection.
 *
 * \par
 * For parcel router internal use only. This function enqueues a request to be
 * send over a struct nuvo_pr_client_conn.  The connection must be in either
 * the NUVO_CCONN_CS_CONNECTING or NUVO_CCONN_CS_CONNECTED states.  If the
 * connection is connected, this function will also invoke
 * nuvo_pr_cconn_process_send on the connection to attempt sending the newly
 * enqueued request over the connection.
 *
 * \par
 * During this operation it is possible that previously submitted requests
 * will complete and need to have their callbacks invoked.  Since it is not
 * limited what functions the callbacks my themselves call, the caller is
 * responsible for invoking the callbacks after all parcel router layer
 * locks have been released.
 *
 * \param conn The client connection to enqueue the request on.
 * \param req The request to enqueue.
 * \param completed_list A list of requests that completed during the
 * operation.
 * \returns On success returns zero or a positive integer.  On failure,
 * returns a negative integer.
 * \retval -NUVO_EINVAL Connection was in an invalid state for this operation.
 */
nuvo_return_t nuvo_pr_cconn_enqueue_req(struct nuvo_pr_client_conn *conn, struct nuvo_io_request *req, struct nuvo_dlist *completed_list);

/**
 * \brief Attempts to send previously queued requests over the connection.
 *
 * \par
 * For parcel router internal use only.  This function attemps to transmit
 * requests that were previously enqueued on the connection, but not
 * entirely transmitted on the connection.  It is possible that a large
 * request could require multiple calls to this function to completely
 * transmit the request's data (e.g. if the network buffers are too small to
 * hold the entire request).  This should only be called on connections that
 * are in the NUVO_CS_CCONN_CONNECTED state.
 *
 * \par
 * During this operation it is possible that previously submitted requests
 * will complete and need to have their callbacks invoked.  Since it is not
 * limited what functions the callbacks my themselves call, the caller is
 * responsible for invoking the callbacks after all parcel router layer
 * locks have been released.
 *
 * \param conn The client connection to work on.
 * \param completed_list A list of requests that completed during the
 * operation.
 * \returns On success returns zero or a positive integer.  On failure,
 * returns a negative integer.
 * \retval -NUOV_E_SEND Call to send for socket failed.
 */
nuvo_return_t nuvo_pr_cconn_process_send(struct nuvo_pr_client_conn *conn, struct nuvo_dlist *completed_list);

/**
 * \brief Attempts to receive data on the connection and process it.
 *
 * \par
 * For parcel router internal use only.  Attempt to receive data on the
 * connection and process it.  If data is received, it is processed and
 * corresponding requests will be completed.  This should only be called on
 * connections that are in the NUVO_CS_CCONN_CONNECTED state.
 *
 * \par
 * During this operation it is possible that previously submitted requests
 * will complete and need to have their callbacks invoked.  Since it is not
 * limited what functions the callbacks my themselves call, the caller is
 * responsible for invoking the callbacks after all parcel router layer
 * locks have been released.
 *
 * \param conn The client connection to work on.
 * \param completed_list A list of requests that completed during the
 * operation.
 * \returns On success returns zero or a positive integer.  On failure,
 * returns a negative integer.
 * \retval -NUVO_E_RECV Connection closed due to call to recv for socket
 *      failing.
 * \retval -NUVO_E_CONN_CLOSED The connection was closed by remote side.
 * \retval -NUVO_E_BAD_HASH Connection closed due to hash verification
 *      failure.
 * \retval -NUVO_EPROTO The connection was closed due to protocol error.
 */
nuvo_return_t nuvo_pr_cconn_process_recv(struct nuvo_pr_client_conn *conn, struct nuvo_dlist *completed_list);

/**
 * \brief Begin opening a client connection.
 *
 * For parcel router internal use only.  Attempts to connect the client
 * connection pointed to by \p conn to the node described by \p node_desc.
 * This will begin the connection process by calling connect(), but the
 * underlying socket will be in non-blocking mode.  Thus a future call to
 * cconn_service will be needed to finish establishing the connection.
 *
 * \param conn The client connection to work on.
 * \param node_desc A pointer to the struct nuvo_pr_node_desc that describes
 * the node.
 * \returns On success returns zero or a positive integer.  On failure,
 * returns a negative integer.
 * \retval -NUVO_ENOMEM Failed to allocate socket.
 * \retval -NUVO_E_SOCK_OPT Failed to set socket options.
 * \retval -NUVO_EINVAL Failed to parse the node's address.
 * \retval -NUVO_E_CONNECT Call to connect failed.
 * \retval -NUVO_E_EPOLL_CTL Failed to add socket to epoll.
 */
nuvo_return_t nuvo_pr_cconn_open(struct nuvo_pr_client_conn *conn, struct nuvo_pr_node_desc *node_desc);

/**
 * \brief Decide what to do after encountering an error
 *
 * For parcel router internal use only.  Called after an error is encountered.
 * For certain errors we will try to restart the connection.  For other errors
 * we may need to do a shutdown and return errors to the caller.  We may create
 * a new reconnecting state for the connection and a queue for the ops that need
 * to be retried.
 *
 * \param conn The client connection to work on.
 * \param close_err The first error encountered that closed the connection.
 * \param close_reason An enum describing why we tore down the connection.
 */
void nuvo_pr_cconn_handle_error(struct nuvo_pr_client_conn *conn,
                                int64_t                     close_err,
                                enum nuvo_conn_close_reason close_reason);

/**
 * \brief Shutdown and release associated resources of a client connection.
 *
 * For parcel router internal use only.  Attempts to shutdown a client
 * connection and release associated resources for the connection.  This will
 * close the socket for the connection, abort all outstanding requests on the
 * connection, and attempt to unlink the connection from the node_desc and
 * free it.  If the node_desc is locked, the connection is left linked and not
 * freed.  It becomes the job of whoever has the node locked to finish cleanup.
 * This is done to avoid a deadlock scenario.
 *
 * \param conn The client connection to work on.
 * \param completed_list A list of requests that completed during the operation.
 * \param close_err The first error encountered that closed the connection.
 * \param close_reason An enum describing why we tore down the connection.
 */
void nuvo_pr_cconn_shutdown(struct nuvo_pr_client_conn *conn,
                            struct nuvo_dlist          *completed_list,
                            int64_t                     close_err,
                            enum nuvo_conn_close_reason close_reason);

/**
 * \brief Allocate a struct nuvo_pr_server_conn.
 *
 * For parcel router internal use only.  This function allocates a struct
 * nuvo_pr_server_conn from the parcel router's pool.
 *
 * \returns Returns a pointer to a struct nuvo_pr_client_conn if successful.
 * If none are left in the pool, a NULL pointer is returned.
 */
struct nuvo_pr_server_conn *nuvo_pr_sconn_alloc();

/**
 * \brief Free a struct nuvo_pr_server_conn.
 *
 * For parcel router internal use only.  This function frees a struct
 * nuvo_pr_server_conn that was previously allocated by nuvo_pr_sconn_alloc.
 */
void nuvo_pr_sconn_free(struct nuvo_pr_server_conn *conn);

/**
 * \brief Attempt to receive data on connection and process it.
 *
 * For parcel router internal use only. This function attempts to receive
 * any available data on the connection socket and process it accordingly.
 * Requests received on the connection will be passed to the parcel manager
 * to be executed.
 *
 * \param conn The connection to be processed.
 * \returns Returns zero or a positive integer on success.  On failure,
 * returns a negative integer.
 * \retval -NUVO_E_RECV Connection closed due to recv call failure.
 * \retval -NUVO_E_CONN_CLOSED Connection closed by remote side.
 * \retval -NUVO_E_BAD_HASH Connection closed due to hash verification
 *      failure.
 */
nuvo_return_t nuvo_pr_sconn_process_recv(struct nuvo_pr_server_conn *conn);

/**
 * \brief Attempt to send data on a connection.
 *
 * For parcel router internal use only.  This function attempts to send data
 * for a previously queued request on the connection.  For large requests,
 * this function may need to be called multiple times to transfer all of the
 * request's data (e.g. if the data is larger than network buffers).
 *
 * \param conn The connection to be processed.
 * \returns Returns zero or a positive integer on success.  On failure,
 * returns a negative integer.
 * \retval -NUVO_E_SEND Connection closed due to send call failure.
 */
nuvo_return_t nuvo_pr_sconn_process_send(struct nuvo_pr_server_conn *conn);

/**
 * \brief Decide what to after encountering an error
 *
 * For parcel router internal use only.  Called after an error is encountered.
 * For certain errors we will try to restart the connection.  For other errors
 * we may need to do a shutdown and return errors to the caller.  We may create
 * a new reconnecting state for the connection and a queue for the ops that need
 * to be retried.
 *
 * \param conn The client connection to work on.
 * \param close_err The first error encountered that closed the connection.
 * \param close_reason An enum describing why we tore down the connection.
 */
void nuvo_pr_sconn_handle_error(struct nuvo_pr_server_conn *conn,
                                int64_t                     close_err,
                                enum nuvo_conn_close_reason close_reason);

/**
 * \brief Shutdown and release associated resources of a server connection.
 *
 * For parcel router internal use only.  Attempts to shutdown a server
 * connection and release associated resources for the connection.  This will
 * close the socket for the connection, abort all outstanding requests on the
 * connection, and free it.
 *
 * \param conn The server connection to work on.
 * \param close_err The first error encountered that closed the connection.
 * \param close_reason An enum describing why we tore down the connection.
 */
void nuvo_pr_sconn_shutdown(struct nuvo_pr_server_conn *conn,
                            int64_t                     close_err,
                            enum nuvo_conn_close_reason close_reason);

/**
 * \brief Initialize a nuvo_pr_req_pool for use.
 *
 * This function initializes a newly allocated struct nuvo_pr_req_pool such
 * that it is ready for use afterwards.
 *
 * \returns On success, returns zero or a positive integer.  On failure,
 * returns a negative integer.
 * \retval -NUVO_ENOMEM Failed to initialize mutex.
 */
nuvo_return_t nuvo_pr_req_pool_init(struct nuvo_pr_req_pool *req_pool);

/**
 * \brief Performs cleanup and releases any resources used by a struct
 * nuvo_pr_req_pool.
 */
void nuvo_pr_req_pool_destroy(struct nuvo_pr_req_pool *req_pool);

/**
 * \brief Allocate a struct nuvo_io_request.
 *
 * This function attempts to allocate
 * a struct nuvo_io_request from the request pool in nuvo_pr.
 *
 * \returns If a struct nuvo_io_request was available and was allocated, a
 * pointer to it is returned.  Otherwise, NULL is returned.
 */
struct nuvo_io_request *nuvo_pr_req_alloc(struct nuvo_pr_req_pool *req_pool);

/**
 * \brief Allocate a struct nuvo_io_request with callback completion.
 *
 * This function registers an allocation
 * request for a struct nuvo_io_request with the allocator.  The allocation
 * is queued with the allocator and will complete after previously queued
 * allocations complete.  If there is a nuvo_io_request available in the pool
 * when the function is invoked, the allocation is done and the callback is
 * invoked immediately.  If there are none available, then the allocator waits
 * until one is freed, and will invoke the callback immediately when a request
 * becomes available.  The provided struct nuvo_pr_req_alloc pointed to by \p
 * alloc contains the callback to be invoked, a pointer to the allocated
 * struct nuvo_io_request, and a tag for use by the caller.
 *
 * \param req_pool The pool the rquest belongs to.
 * \param alloc The allocation request information.
 */
void nuvo_pr_req_alloc_cb(struct nuvo_pr_req_pool *req_pool, struct nuvo_pr_req_alloc *alloc);

/**
 * \brief Frees a struct nuvo_io_request.
 *
 * This function frees a struct
 * nuvo_io_request that was previously allocated by either nuvo_pr_req_alloc,
 * or nuvo_pr_req_alloc_cb.
 */
void nuvo_pr_req_free(struct nuvo_pr_req_pool *req_pool, struct nuvo_io_request *req);

/**
 * \brief Allocate a struct nuvo_pr_pdef from the nuvo_pr pool.
 *
 * For parcel router internal use only.  This function attempts to allocate
 * a struct nuvo_pr_pdef from the pool in nuvo_pr.
 *
 * \returns If a struct nuvo_pr_pdef is available and is allocated, a pointer
 * to it is returned.  Otherwise, NULL is returned.
 */
_Atomic struct nuvo_pr_pdef *nuvo_pr_pdef_alloc();

/**
 * \brief Free a struct nuvo_pr_def.
 *
 * For parcel router internal use only.  This function frees a struct
 * nuvo_pr_pdef that was previously allocated by nuvo_pr_pdef_alloc.
 */
void nuvo_pr_pdef_free(_Atomic struct nuvo_pr_pdef *pdef);

/**
 * \brief Removes all parcel definitions associated with a particular node.
 *
 * For parcel router internal use only.  This function removes all active
 * parcel definition records that link to the node descriptor pointed to by
 * \p node_desc.  This is done via a linear scan.  All parcel definitions
 * found will be invalidated and freed.
 *
 * \param node_desc Pointer to a struct nuvo_pr_node_desc representing the
 * node targeted.
 */
void nuvo_pr_pdef_remove_all(struct nuvo_pr_node_desc *node_desc);

/**
 * \brief Generate a parcel_descriptor to match a nuvo_pr_pdef.
 *
 * For parcel router internal use only.  This function generates a struct
 * parcel_descriptor that will describe the struct nuvo_pr_pdef pointed to by \p
 * pdef.  For a pdesc to correctly describe a struct nuvo_pr_pdef it must
 * contain the corresponding index and also a matching gen.  If the gen does
 * not match, the pdesc is considered invalid.  The gen of a nuvo_pr_pdef
 * increases every time it is reused to represent a different parcel_desc.
 *
 * \param pdef The struct nuvo_pr_pdef used to generate a parcel_descriptor.
 */
union parcel_descriptor nuvo_pr_pdef_to_pdesc(_Atomic struct nuvo_pr_pdef *pdef);

/**
 * \brief Atomically get the value of a struct nuvo_pr_pdef described by \p
 * pdesc.
 *
 * For parcel router internal use only.  This function atomically verifies
 * that \p pdesc correctly describes a struct nuvo_pr_pdef and retrieves the
 * value of that struct nuvo_pr_pdef and stores it in to \p *pdef.
 *
 * \param pdesc A union parcel_descriptor that describes an active struct
 * nuvo_pr_pdef.
 * \param pdef A pointer to where to store the value of the struct
 * nuvo_pd_pdef described by pdesc.
 * \returns If \p pdesc correctly described an active struct nuvo_pr_pdef, zero
 * or a positive integer is returned.  Otherwise, a negative integer is
 * returned.
 * \retval -NUVO_EINVAL Parameter pdesc is not a valid parcel descriptor.
 */
nuvo_return_t nuvo_pr_pdef_get(union parcel_descriptor pdesc,
                               struct nuvo_pr_pdef    *pdef);

/**
 * \brief Atomically add \p val to the number of outstanding requests for the
 * struct nuvo_pr_pdef described by \p pdesc.
 *
 * For parcel router internal use only.  This function atomically adds \p val
 * to the number of outstanding requests for the struct nuvo_pr_pdef described
 * by \p pdesc.  Val can be positive or negative, allowing for increasing or
 * decreasing the number of outstanding requests respectively.  The pdesc must
 * correctly describe an active struct nuvo_pr_pdef for the function to
 * succeed.
 *
 * \param pdesc A union parcel_descriptor that describes an active struct
 * nuvo_pr_pdef.
 * \param val An integer value to add to the current outstanding count.
 * \returns If \p pdesc correctly described an active struct nuvo_pr_pdef, zero
 * or a positive integer is returned.  Otherwise, a negative integer is
 * returned.
 * \retval -NUVO_EINVAL Parameter pdesc is not a valid parcel descriptor.
 */
nuvo_return_t nuvo_pr_pdef_add_outstanding(union parcel_descriptor pdesc, int_fast32_t val);

/**
 * \brief Initialize a nuvo_pr_buf_pool for use.
 *
 * For parcel router internal use only.
 * This function initializes a newly allocated struct nuvo_pr_buf_pool such
 * that it is ready for use afterwards.
 *
 * \param buf_pool A pointer to the struct nuvo_pr_buf_pool to initialize.
 * \returns On success, returns zero or a positive integer.  On failure,
 * returns a negative integer.
 * \retval -NUVO_ENOMEM Failed to initialize mutex.
 */
nuvo_return_t nuvo_pr_buf_pool_init(struct nuvo_pr_buf_pool *buf_pool);

/**
 * For parcel router internal use only.
 * \brief Performs cleanup and releases any resources used by a struct
 * nuvo_pr_buf_pool.
 *
 * \param buf_pool A pointer to the struct nuvo_pr_buf_pool to destroy.
 */
void nuvo_pr_buf_pool_destroy(struct nuvo_pr_buf_pool *buf_pool);

/**
 * \brief Check for pending buffer allocation requests and completes them if
 * possible.
 *
 * For parcel router internal use only.  This function checks for pending
 * buffer allocation requests and completes them if there are available
 * buffers.  Upon completion, the struct nuvo_pr_buf_alloc is dequeued from
 * the internal list, the buffer pointers are stored into the
 * req->rw.iovecs[].iov_base fields, and the callback is invoked.  Note that
 * this function is invoked on every allocate and free.  Thus callbacks may
 * not be called immediately, and they may be called from other threads that
 * call free.
 *
 * \param buf_pool A pointer to the struct nuvo_pr_buf_pool to check.
 * \param list A list to put the completed allocation requests.
 */
void nuvo_pr_buf_check_allocs(struct nuvo_pr_buf_pool *buf_pool, struct nuvo_dlist *list);

/**
 * \brief Attempts to allocate a buffer.
 *
 * For parcel router internal use only.
 * This function attempts to allocate a buffer from the pool in nuvo_pr.
 *
 * \param buf_pool A pointer to the struct nuvo_pr_buf_pool to allocate from.
 * \returns If a buffer is available, returns a pointer to the allocated
 * buffer.  Otherwise, returns NULL.
 */
void *nuvo_pr_buf_alloc(struct nuvo_pr_buf_pool *buf_pool);

/**
 * \brief Allocates buffers for a request with a callback completion.
 *
 * For parcel router internal use only.
 * This function registers an allocation request for multiple buffers as
 * needed for a request.  The alloc->req->rw.block_count field is used to
 * indicate the number of buffers needed.  If the allocator has enough
 * buffers available, and there are no other pending allocation requests,
 * the allocation is completed immediately and pointers to
 * the allocated buffers are stored in the alloc->req->rw.iovecs[].iov_base
 * fields.  If there are not enough buffers available, the allocation request
 * queued and will eventually complete when the necessary requests are freed.
 * Note that this can result in requests being completed when buffers are
 * freed from other threads, thus the callbacks may be invoked from other
 * threads.
 *
 * \param buf_pool A pointer to the struct nuvo_pr_buf_pool to allocate from.
 * \param alloc A pointer to the allocation request information.
 */
void nuvo_pr_buf_alloc_batch(struct nuvo_pr_buf_pool *buf_pool, struct nuvo_pr_buf_alloc *alloc);

/**
 * \brief Free a buffer.
 *
 * For parcel router internal use only.
 * This function frees a buffer that was previously allocated by either
 * nuvo_pr_buf_alloc or nubo_pr_buf_alloc_batch.
 *
 * \param buf_pool A pointer to the struct nuvo_pr_buf_pool that \p buf was
 * allocated from.
 * \param buf A pointer to the buffer to be freed.
 */
void nuvo_pr_buf_free(struct nuvo_pr_buf_pool *buf_pool, void *buf);

/**
 * \brief Frees a number of buffers for a request.
 *
 * For parcel router internal use only.
 * This function frees a number of buffers that were previously allocated by
 * either nuvo_pr_buf_alloc or nuvo_pr_buf_alloc_batch.  This function
 * accomplishes the same result as calling nuvo_pr_buf_free on the
 * req->rw.iovecs[n].iov_base pointers used by the request (i.e. the first
 * req->rw.block_count buffers).  However, this function is more efficient
 * than simply looping and calling nuvo_pr_buf_free and is thus prefered for
 * freeing a batch of buffers that was used for a particular request.
 *
 * \param buf_pool A pointer to the struct nuvo_pr_buf_pool that \p buf was
 * allocated from.
 * \param req A pointer to the struct nuvo_io_request whose buffers to free.
 */
void nuvo_pr_buf_free_req(struct nuvo_pr_buf_pool *buf_pool, struct nuvo_io_request *req);
void nuvo_pr_buf_free_list(struct nuvo_pr_buf_pool *buf_pool, void **buf_list, uint_fast32_t count);

/**
 * \brief Get a connection to a node, opening it if needed.
 *
 * For parcel router internal use only.  This function gets a connection to
 * the node described by \p node.  If an established connection exists, it is
 * returned.  If no connection exists, a struct nuvo_pr_client_conn is
 * allocated and the connecting process is started.  This function also deals
 * with cleaning up shutdown connections that have had part of their clean-up
 * deferred to avoid a deadlock.  The parameter \p open_conn determines if the
 * function should open a new connection if one does not already exist.
 *
 * \param node A pointer to the struct nuvo_pr_node_desc describing the node
 * to which we want a connection to.
 * \param conn A pointer to where the resulting pointer to the connection
 * should be stored.
 * \param open_conn A boolean determining if a new connection should be opened
 * if one does not already exist.
 * \returns Returns zero or a positive integer if a connection is successfully
 * returned.  Otherwise, a negative integer is returned.
 * \retval -NUVO_ENOTCONN No existing connection to node, open_conn was false.
 * \retval -NUVO_ENOMEM No exiting connection and failed to allocate
 *      connection structures.
 * \retval -NUVO_E_CONNECT No existing connection and failed to open a new
 *      connection.
 */
nuvo_return_t nuvo_pr_get_conn(struct nuvo_pr_node_desc *node, struct nuvo_pr_client_conn **conn, bool open_conn);

/**
 * \brief Create the server listen socket and start listening for connections
 */
nuvo_return_t nuvo_pr_server_sock_init(uint_fast16_t server_port);

/**
 * \brief Initialize the connection manager.
 *
 *  Initialize locks and create the connection manager thread.
 */
nuvo_return_t nuvo_pr_conn_mgr_init();

/**
 * \brief Tear down the connection manager.
 *
 * Terminate the thread and destroy connection manager locks.
 */
void nuvo_pr_conn_mgr_destroy();

/**
 * \brief How long we should wait before attempting a socket reconnect in ns.
 *
 * \returns value in nano seconds we should wait before next retry
 */
uint64_t nuvo_pr_cconn_get_backoff_ns(struct nuvo_pr_client_conn *conn);

/**
 * \brief Get a client connection that needs error recovery.
 *
 * Traverse the list of active connections, and find one that is in an
 * error state and needs to be reconnected.  If a connection has attempted
 * recovery within the last second, it will be skipped.  This connection
 * will be retried again later.
 *
 * \returns connection which needs recovery or NULL
 */
struct nuvo_pr_client_conn *nuvo_pr_get_recovery_cconn();

/**
 * \brief Main function for starting recovery of a failed client connection
 *
 * The rest of recovery will be completed by nuvo_pr_cconn_recovery_resend()
 * after the conn_mgr is notified that the socket is ready to send data.
 *
 * Handles reconnecting the socket for a client connection
 * High level steps:
 * Move in flight requests to retry list
 * Tear down the socket which encountered the error
 * Attempt to reconnect socket
 */
void nuvo_pr_cconn_recovery_start(struct nuvo_pr_client_conn *conn);

/**
 * \brief Compelete the recovery for a failed client connection
 *
 * Called after the socket is ready to send data
 * High level steps:
 * Send requests on retry list
 * Update socket state to NUVO_CCCS_CONNECTED
 * Send requests queued during recovery (wait list)
 *
 * \param conn The connection to be processed.
 */
void nuvo_pr_cconn_recovery_resend(struct nuvo_pr_client_conn *conn);

/**
 * \brief Move all in flight ops to the retry queue
 *
 * Any ops that were in flight are added in order to a retry queue
 * This includes all ops on the pending list and the req currently being
 * worked on (conn->send_req).
 *
 * \param conn The connection to be processed.
 */
void nuvo_pr_cconn_move_to_retry_q(struct nuvo_pr_client_conn *conn);

/**
 * \brief Try to reconnect the socket for the given client connection
 *
 * Removes socket from epoll, and then attempts to reconnect.
 * Will attempt to close and reopen socket up to 10 times.
 *
 * \param conn The connection to be processed.
 * \returns 0 on success, -NUVO_E_* on failure
 */
nuvo_return_t nuvo_pr_cconn_recover_socket(struct nuvo_pr_client_conn *conn);

/**
 * \brief Process events received from epoll during connection recovery
 *
 * This handles operations that are sent during the recovery of a connection.
 * There are three main types of events to process:
 * 1) Notification that the socket is up and ready to use
 * 2) Ops for restablishing state between nodes after a remote nuvo crash/reboot
 * 3) Ops that are resent from the retry queue (in flight during the failure)
 *
 * \param conn The connection to be processed.
 * \param events The set of events found by epoll.
 * \param completed_list A list of requests completed during the operation.
 */
void nuvo_pr_cconn_recovery_epoll_event(struct nuvo_pr_client_conn *conn,
                                        uint32_t                    events,
                                        struct nuvo_dlist          *completed_list);

/**
 * \brief During connection recovery, update native parcel descriptors
 *
 * We issue parcel opens on all of the previously opened parcels during
 * connection recovery.  We get a native parcel descriptor back from the
 * remote node, and all the inflight or queued operations should use the new
 * native parcel descriptor.  This function steps through the req_retry_list
 * and req_wait_list and updates all the reqs with the new parcel descriptors.
 *
 * \param conn The connection to be processed.
 */
void nuvo_pr_cconn_update_pdescs(struct nuvo_pr_client_conn *conn);

/**
 * \brief Wrapper that sends requests which were queued during cconn recovery
 *
 * Depending on the connection state, will either send requests queued on
 * the retry list or the wait list.
 *
 * \param conn The connection to be processed.
 * \returns 0 on success, -NUVO_E_* on failure
 */
nuvo_return_t nuvo_pr_cconn_resend_reqs(struct nuvo_pr_client_conn *conn);

/**
 * \brief Wrapper that does a socket read for reqs acked during cconn recovery
 *
 * Call into nuvo_pr_cconn_process_recv() to process any reqs that were
 * acked during recovery.
 *
 * \param conn The connection to be processed.
 * \returns 0 on success, -NUVO_E_* on failure
 */
nuvo_return_t nuvo_pr_cconn_check_recv(struct nuvo_pr_client_conn *conn);

/**
 * \brief We successfully reconnected the socket.
 *
 * The conn_mgr is done with it's work on this connection.
 * We have restablished the connection and started listening for socket
 * events in the client_thread.  The conn is back on the active list.
 *
 * \param conn The connection to be processed.
 */
void nuvo_pr_cconn_recovery_complete(struct nuvo_pr_client_conn *conn);

/**
 * \brief Give up on reconnecting the socket, do a shutdown on the conneciton
 *
 * \param conn The connection to be processed.
 */
void nuvo_pr_cconn_recovery_failed(struct nuvo_pr_client_conn *conn);

/**
 * \brief Get a server connection that needs error recovery.
 *
 * Traverse the list of active connections and find one that is in an
 * error state and needs to be reconnected.
 *
 * \returns connection which needs recovery or NULL
 */
struct nuvo_pr_server_conn *nuvo_pr_get_recovery_sconn();

/**
 * \brief Responsible for doing recovery of a failed server connection
 *
 * Easier than client connection recovery, we are just going to throw
 * out everything that was in flight.  All in flight requests will be resent
 * by the client side.
 *
 * \param conn The connection to be processed.
 */
void nuvo_pr_sconn_recovery_start(struct nuvo_pr_server_conn *conn);

/**
 * \brief Check if we currently support retries for this op type
 *
 * Initially we will only support retries for reads/writes.  Once the PM makes
 * all these ops idem potent, we can remove this function.
 *
 * \param req to check
 * \returns if we currently support retries for this op type
 */
bool nuvo_pr_is_retriable_req(struct nuvo_io_request *req);

/**
 * \brief Wait for a socket to be ready.
 *
 * Wait till we get an event from the socket, up to the specified timeout.
 * May remove if the connection states get integrated with epoll.
 * Wanted to keep recovery happening in separate thread.
 *
 * \param sock_fd the socket fd we will wait on
 * \param timeout the time in seconds we will wait before giving up.
 * \returns 0 on success, -NUVO_E_* on failure
 */
nuvo_return_t nuvo_pr_socket_poll_wait(int sock_fd, int timeout);

/**
 * \brief Process client side socket events received from epoll
 *
 * This is called from two different threads to handle the epoll for client
 * side sockets.  The healthy path is called from the client thread, which only
 * handles healthy connections.  The recovering (unHealthy) path is driven by
 * the conn_mgr and the epoll happens on a recovering epoll_fd.
 * A connection will only be on one epoll at a time.
 *
 * TODO: According to the manpage, sigset is obsolete. We should update to
 * the newer sigaction/sigprocmask.
 *
 * \param sigset used the socket fd we will wait on
 * \param timeout the time in seconds we will wait before giving up.
 */
void nuvo_pr_cconn_process_epoll(sigset_t *sigset, bool is_healthy);

/**
 * \brief Move socket from one epoll list to another
 *
 * The client_thread does epolling for healthy connections, and the
 * conn_mgr does epolling for recovering connections.  This function moves
 * them back and forth.
 *
 * Can also add to epoll with a -1 value for epoll_fd_from
 * Can also remove from epoll with a -1 value for epoll_fd_to
 *
 * \param conn The connection to be processed.
 * \param epoll_fd_from the fd of the epoll we are removing the conn from
 * \param epoll_fd_to the fd of the epoll we are adding the conn to
 * \returns 0 on success, -NUVO_E_* on failure
 */
nuvo_return_t nuvo_pr_cconn_epoll_move(struct nuvo_pr_client_conn *conn,
                                       int epoll_fd_from, int epoll_fd_to);

/**
 * \brief Wrapper function to add socket to epoll list
 *
 * \param conn The connection to be processed.
 * \param epoll_fd the fd of the epoll we are adding the conn to
 * \returns 0 on success, -NUVO_E_* on failure
 */
nuvo_return_t nuvo_pr_cconn_epoll_add(struct nuvo_pr_client_conn *conn,
                                      int                         epoll_fd);

/**
 * \brief Wrapper function to remove socket to epoll list
 *
 * \param conn The connection to be processed.
 * \param epoll_fd the fd of the epoll we are removing the conn from
 * \returns 0 on success, -NUVO_E_* on failure
 */
nuvo_return_t nuvo_pr_cconn_epoll_remove(struct nuvo_pr_client_conn *conn,
                                         int                         epoll_fd);

/**
 * \brief For certain op types, modify error return codes to success
 *
 * In order to provide idempotent operations, we modify specific error codes
 * for some config ops from failure to success.  For example, if we open
 * a parcel that is already open, rather than return an error we will
 * return succcess.
 *
 * \param req The request which may have it's status translated
 */
void nuvo_pr_idempotent_status_set(struct nuvo_io_request *req);

/**
 * \brief Check if this is a special op sent to restablish state on the server
 *
 * \param req The request to check
 * \returns true If the request is a config op being resent during conn recovery
 * \returns false If the request is a normal op
 */
bool nuvo_pr_is_resend_config_req(struct nuvo_io_request *req);

/**
 * \brief Check the connections open parcel list for the parcel.
 *
 * \param parcel_desc The parcel we are looking for
 * \param cconn The conn the request is being sent over
 * \returns parcel_info if found, NULL if not found
 */
struct nuvo_pr_parcel_info *nuvo_pr_find_parcel_open_info(uint32_t                    parcel_desc,
                                                          struct nuvo_pr_client_conn *cconn);

/**
 * \brief Add parcel info for the newly opened parcel.
 *
 * \param req The open request that just completed successfully.
 * \param cconn The conn tracking the open parcel
 * \returns 0 on success, -NUVO_E_* on failure
 */
nuvo_return_t nuvo_pr_add_parcel_open_info(struct nuvo_io_request     *req,
                                           struct nuvo_pr_client_conn *cconn);

/**
 * \brief Remove the parcel from the list and free the associated memory.
 *
 * \param parcel_desc The parcel we are removing from the list
 * \param cconn The conn tracking the open parcel
 */
void nuvo_pr_remove_parcel_open_info(uint32_t                    parcel_desc,
                                     struct nuvo_pr_client_conn *cconn);

/**
 * \brief If a volume has a network unreachable parcel, update the vol state
 *
 * Step through all the parcels routed through this connection. If a volume
 * is using any of the parcels, mark the volume unhealthy.  When the
 * connection recovers, mark the volume healthy.
 *
 * TODO: This needs to be enhanced.  The single flag is placeholder, in the
 * future when volumes could be spread across multiple nodes the volume needs
 * to wait until are parcels are available before being marked healthy.
 *
 * \param cconn The conn that encountered a failure or is recovering
 * \param bool If we are marking the volume healthy or unhealthy
 */
void nuvo_pr_update_volumes_health(struct nuvo_pr_client_conn *cconn,
                                   bool                        healthy);

/**
 * \brief Resend open requests to reestablish state on the server
 *
 * There is a in-core list of open parcels, with each struct containing the
 * info required to reopen it.  This function moves all parcels from the open
 * parcel list to a reopen list for processing.  Then it resends open requests
 * for all of the previously open parcels.  nuvo_pr_reopen_complete_callback()
 * will handle the reopen responses and transition the connection state
 * once the last parcel open is received.
 *
 * \param cconn The conn that encountered a failure or is recovering
 * \returns 0 on success, -NUVO_E_* on failure
 */
nuvo_return_t nuvo_pr_cconn_resend_opens(struct nuvo_pr_client_conn *cconn);

/**
 * \brief Callback routine for resend open requests
 *
 * This callback routine handles the responses from the server for requests
 * sent by nuvo_pr_cconn_resend_opens().  When the last open request is
 * received, we will move the connection to the next recovery state.
 *
 * \param req The reopen request that just completed.
 */
void nuvo_pr_reopen_complete_callback(struct nuvo_io_request *req);

/**
 * \brief TEST ONLY - Trigger fault injection for op on the server send side
 *
 * This triggers fault injection on the server side after the op completes.
 * Rather than send the ack back, the connection is torn down.  This means
 * the client send will resend the op, and test idempotent behavior.
 */
bool nuvo_pr_fi_idempotent_error(struct nuvo_io_request *req);

/**
 * \brief TEST ONLY - Log some pr stats, requests in client conn queues.
 */
void nuvo_pr_log_cconn_queues(struct nuvo_pr_client_conn *cconn);

/**
 * \brief TEST ONLY - Log some pr stats, requests in server conn queues.
 */
void nuvo_pr_log_sconn_queues(struct nuvo_pr_server_conn *sconn);
