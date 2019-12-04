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

#pragma once

#include <assert.h>
#include <libaio.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <uuid/uuid.h>
#include <sys/uio.h>
#include <stdatomic.h>
#include <stdbool.h>

#include "nuvo_list.h"
#include "nuvo_lock.h"
#include "nuvo_hash.h"
#include "status.h"
#include "parallel.h"
#include "parcel_manager.h"

/** The maximum number of blocks we support for any IO operation. */
#define NUVO_MAX_IO_BLOCKS           (256)
/** The maximum size we support for any IO operation. */
#define NUVO_MAX_IO_SIZE             (NUVO_BLOCK_SIZE * NUVO_MAX_IO_BLOCKS)

/** The amount of memory to allocate for buffers. */
#define NUVO_BUF_MEM                 (64ull * 1024 * 1024)

/** The number of bits used to store the retry cnt. */
#define NUVO_PR_MAX_OP_RETRY_BITS    (7)

/** The number of times we will retry a given operation before giving up. */
#define NUVO_PR_MAX_OP_RETRIES       ((1ull << NUVO_PR_MAX_OP_RETRY_BITS) - 1ull)

/** A structure for describing nuvo_io_request allocation requests. */
struct nuvo_pr_req_alloc {
    struct nuvo_dlnode      list_node;
    void                    (*callback)(struct nuvo_pr_req_alloc *alloc);
    struct nuvo_io_request *req;
    union nuvo_tag          tag;
};

/** A structure for describing buffer allocation requests. */
struct nuvo_pr_buf_alloc {
    struct nuvo_dlnode list_node;
    void               (*callback)(struct nuvo_pr_buf_alloc *alloc);
    union
    {
        struct nuvo_io_request *req;
        void                  **buf_list;
    };
    union nuvo_tag     tag;
    uint_fast32_t      buf_count;
};

struct nuvo_pr_server_conn;

/** IO origin classification */
enum nuvo_io_origin
{
    NUVO_IO_ORIGIN_USER = 0,    /**< The IO that orginated on the active lun.*/
    NUVO_IO_ORIGIN_GC_DATA,     /**< The data IO originated from GC (not including digest and map I/O triggered by GC */
    NUVO_IO_ORIGIN_INTERNAL     /**< The IO originated in the Map, GC (except GC data), or on the non-active lun (ie. backup). */
};

enum nuvo_cache_hint
{
    NUVO_CACHE_DEFAULT = 0,     /**< Default is to use the cache. */
    NUVO_CACHE_NONE    = 1      /**< Don't cache data. */
};

/** An enumeration of all the of supported request operations. */
enum nuvo_op
{
    NUVO_OP_READ = 0,
    NUVO_OP_WRITE,
    NUVO_OP_OPEN,
    NUVO_OP_CLOSE,
    NUVO_OP_ALLOC,
    NUVO_OP_FREE,
    NUVO_OP_DEV_INFO,
    NUVO_OP_READ_VERIFY
};

/** The parcel status tracks the health of a parcel. */
enum nuvo_pr_parcel_status
{
    NUVO_PR_PARCEL_UNAVAILABLE = 0,  /** The parcel can't be reached. */
    NUVO_PR_PARCEL_HEALTHY,          /** The parcel is healthy. */
    NUVO_PR_PARCEL_DEGRADED          /** Future, state for degraded mirror. */
};

/**
 * \brief A structure representing information for one request.
 *
 * The nuvo_io_request is used to store information related to a request.
 * Some of the fields are reserved for use only by specific software layers
 * to store layer-specific information.  Below is a breakdown of which fields
 * are used where.
 *
 * A request is first populated by the caller of nuvo_pr_submit before it
 * is submitted to the parcel router layer.  The fields that must be filled in
 * vary depending on the type of operation submitted:
 * - For all operations
 *   + operation - one of the operations in the enum nuvo_op.
 *   + tag - a union nuvo_tag that is strictly for the caller's use.
 *   + callback - a callback function to be invoked on completion.
 * - NUVO_OP_READ
 *   + rw.parcel_desc - the parcel descriptor of the parcel to read from.
 *   + rw.block_offset - the block offset within the parcel in number of blocks.
 *   + rw.block_count - the number of blocks to read.
 *   + rw.iovecs[] - the first rw.block_count of these should have buffers
 * of size NUVO_BLOCK_SIZE filled in with the buffers where the read data will
 * be placed.
 * - NUVO_OP_READ_VERIFY
 *   + rw.parcel_desc - the parcel descriptor of the parcel to read from
 *   + rw.block_offset - the block offset within the parcel in number of blocks.
 *   + rw.block_count - the number of blocks to read.
 *   + rw.iovecs[] - the first rw.block_count of these should have buffers
 * of size NUVO_BLOCK_SIZE filled in with the buffers where the read data will
 * be placed.
 *   + rw.block_hashes - the first rw.block_count of the blocks read from media
 * should have hashes matching the corresponding values.
 * - NUVO_OP_WRITE
 *   + rw.parcel_desc - the parcel descriptor of the parcel to write to.
 *   + rw.block_offset - the block offset within the parcel in number of blocks.
 *   + rw.block_count - the number of blocks to write.
 *   + rw.iovecs[] - the first rw.block_count of these should have buffers
 * of size NUVO_BLOCK_SIZE filled in with buffers containing the data to be
 * written
 *   + rw.block_hashes - the first rw.block_count of these should have hash
 * values matching the contents of each of the buffers in rw.iovecs[].
 * - NUVO_OP_OPEN
 *   + open.parcel_uuid - the UUID of the parcel to open.
 *   + open.device_uuid - the UUID of the device that contains the parcel.
 *   + open.volume_uuid - the UUID of the volume that owns the parcel.
 * - NUVO_OP_CLOSE
 *   + close.parcel_desc - the parcel descriptor to close.
 * - NUVO_OP_ALLOC
 *   + alloc.device_uuid - the device on which to allocate a parcel.
 *   + alloc.volume_uuid - the volume that is allocating the parcel.
 * - NUVO_OP_FREE
 *   + free.parcel_uuid - the UUID of the parcel to be freed.
 *   + free.device_uuid - the UUID of the device that contains the parcel.
 *   + free.volume_uuid - the UUID of the volume that owns the parcel.
 * - NUVO_OP_DEV_INFO
 *   + dev_info.device_uuid - the UUID of the device to get info from.
 *
 * After a request is completed and its callback is invoked, the following
 * fields contain return data for the submitter.
 * - For all operations
 *   + status - the status code indicating if the operation succeeded.
 * - NUVO_OP_READ
 *   + rw.iovecs[].iov_base - the first rw.block_count of these buffers
 * should contain the read data
 *   + rw.block_hashes[] - the first rw.block_count of these should contain
 * hash values matching the data in the read buffers.
 * - NUVO_OP_WRITE
 * - NUVO_OP_OPEN
 *   + open.parcel_desc - the newly opened parcel descriptor.
 * - NUVO_OP_ALLOC
 *   + alloc.parcel_uuid - the UUID of the newly allocated parcel.
 * - NUVO_OP_FREE
 * - NUVO_OP_DEV_INFO
 *   + dev_info.device_size - the size of the device.
 *   + dev_info.parcel_size - the size of parcels on the device.
 *
 * The following field is for parcel router use only.
 * - open.client_pdef
 *
 * After a request is routed through the parcel router layer, it is submitted
 * to the parcel manager via the nuvo_pm_submit function.  The following
 * following fields must be filled in before the parcel router submits a
 * request to the parcel manager.
 *
 * - For all operations
 *   + operation - one of the operations in the enum nuvo_op.
 * - NUVO_OP_READ
 *   + rw.native_parcel_desc - the native parcel descriptor of the parcel to
 * read from.
 *   + rw.block_offset - the block offset within the parcel in number of blocks.
 *   + rw.block_count - the number of blocks to read.
 *   + rw.iovecs[] - the first rw.block_count of these should have buffers
 * of size NUVO_BLOCK_SIZE filled in with the buffers where the read data will
 * be placed.
 * - NUVO_OP_WRITE
 *   + rw.native_parcel_desc - the native parcel descriptor of the parcel to
 * write from.
 *   + rw.block_offset - the block offset within the parcel in number of blocks.
 *   + rw.block_count - the number of blocks to write.
 *   + rw.iovecs[] - the first rw.block_count of these should have buffers
 * of size NUVO_BLOCK_SIZE filled in with buffers containing the data to be
 * written
 *   + rw.block_hashes - the first rw.block_count of these should have hash
 * values matching the contents of each of the buffers in rw.iovecs[].
 * - NUVO_OP_OPEN
 *   + open.parcel_uuid - the UUID of the parcel to open.
 *   + open.device_uuid - the UUID of the device that contains the parcel.
 *   + open.volume_uuid - the UUID of the volume that owns the parcel.
 * - NUVO_OP_CLOSE
 *   + close.parcel_desc - the parcel descriptor to close.
 * - NUVO_OP_ALLOC
 *   + alloc.device_uuid - the device on which to allocate a parcel.
 *   + alloc.volume_uuid - the volume that is allocating the parcel.
 * - NUVO_OP_FREE
 *   + free.parcel_uuid - the UUID of the parcel to be freed.
 *   + free.device_uuid - the UUID of the device that contains the parcel.
 *   + free.volume_uuid - the UUID of the volume that owns the parcel.
 * - NUVO_OP_DEV_INFO
 *   + dev_info.device_uuid - the UUID of the device to get info from.
 *
 * The following fields are for parcel manager use only.
 * - rw.iocb
 * - alloc.iocb
 * - alloc.pb
 * - alloc.device
 * - free.iocb
 * - free.pb
 * - free.device
 */
struct nuvo_io_request {
    struct nuvo_dlnode          list_node;
    enum nuvo_op                operation;
    union nuvo_tag              tag;
    void                        (*callback) (struct nuvo_io_request *req);
    nuvo_return_t               status;

    uint32_t                    op_retry_cnt           : NUVO_PR_MAX_OP_RETRY_BITS;
    uint32_t                    idempotent_status_flag : 1; // ~24 bits left

    struct nuvo_pr_server_conn *sconn;
    uint_fast64_t               io_submit_time;
    uint_fast64_t               earliest_response;

    union
    {
        struct {
            struct nuvo_vol        *vol;
            uint_fast32_t           parcel_desc;
            uint_fast32_t           block_offset;
            uint_fast32_t           block_count;
            struct iovec            hashes_iovec;
            struct iovec            iovecs[NUVO_MAX_IO_BLOCKS];
            nuvo_hash_t             block_hashes[NUVO_MAX_IO_BLOCKS];

            uint_fast32_t           native_parcel_desc;
            enum nuvo_io_origin     io_origin;
            enum nuvo_cache_hint    cache_hint;
            struct iocb             iocb;
            struct nuvo_parallel_op par_op;
            bool                   *cache_result;      // Used by GC
        } rw;
        struct {
            uuid_t                       parcel_uuid;
            uuid_t                       device_uuid;
            uuid_t                       volume_uuid;
            uint_fast32_t                parcel_desc;

            _Atomic struct nuvo_pr_pdef *client_pdef;

            uint32_t                     reopen_flag; // only set on reopen req
            struct nuvo_pr_parcel_info  *reopen_pi;   // only set on reopen req
        } open;
        struct {
            uint_fast32_t parcel_desc;
            uint_fast32_t native_parcel_desc;
        } close;
        struct {
            uuid_t      parcel_uuid;
            uuid_t      device_uuid;
            uuid_t      volume_uuid;

            struct iocb iocb;
            void       *pb;
            void       *device;
            int32_t     parcelblock_idx;
            int32_t     parcel_idx;
            uint32_t    deferred_flag;
        } alloc;
        struct {
            uuid_t      parcel_uuid;
            uuid_t      device_uuid;
            uuid_t      volume_uuid;

            struct iocb iocb;
            void       *pb;
            void       *device;
            int32_t     parcelblock_idx;
            int32_t     parcel_idx;
            uint32_t    deferred_flag;
        } free;
        struct {
            uuid_t             device_uuid;
            uint64_t           device_size;
            uint64_t           parcel_size;
            enum nuvo_dev_type device_type;
        } dev_info;
    };
};

static_assert(offsetof(struct nuvo_io_request, rw.hashes_iovec) + sizeof(struct iovec) == offsetof(struct nuvo_io_request, rw.iovecs), "Member hashes_iovec of struct nuvo_io_request must be directly before member iovecs[].");

#define NUVO_IS_USER_IO(io_req)                 (io_req->rw.io_origin == NUVO_IO_ORIGIN_USER)
#define NUVO_IS_GC_DATA(io_req)                 (io_req->rw.io_origin == NUVO_IO_ORIGIN_GC_DATA)
#define NUVO_SET_IO_TYPE(io_req, op, origin)    ({ \
        io_req->operation = op;                    \
        io_req->rw.io_origin = origin;             \
    })

#define NUVO_SET_CACHE_HINT(io_req, hint)       ({ \
        io_req->rw.cache_hint = hint;              \
    })

/**
 * \fn nuvo_return_t nuvo_pr_init(const uuid_t local_node_id, uint_fast16_t server_port)
 * \brief Initialize the parcel router layer.
 *
 * This is an initialization function for the parcel router layer.  It
 * allocates the necessary memory, beings listening for network connections, and
 * starts the network polling threads.
 *
 * \param server_port The TCP port on which the parcel router should listen
 * for network connections.
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 * \retval -NUVO_ENOMEM Memory allocation failure, failure to initialize
 *      a mutex, failure to allocate an epoll fd, failure to create a thread,
 *      or failure to create a socket.
 * \retval -NUVO_E_SIG_HANDLER Failed to set process signal handlers.
 * \retval -NUVO_E_SOCK_OPT Failed to set socket options.
 * \retval -NUVO_E_BIND Failed to bind socket.
 * \retval -NUVO_E_SOCK_OPT Failed to set socket options.
 * \retval -NUVO_E_LISTEN Failed to start listening on socket.
 * \retval -NUVO_E_EPOLL_CTL Failed to add socket to epoll.
 */
nuvo_return_t nuvo_pr_init(uint_fast16_t server_port);

/**
 * \fn nuvo_return_t nuvo_pr_set_node_uuid(const uuid_t local_node_id);
 * \brief Set the node uuid for this node and start services.
 *
 * Processes are waiting for the node uuid to be set. This function
 * will set the node uuid and start services.
 * \param local_node_id uuid to be used by this node
 *
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 * \retval -NUVO_EEXIST Local node UUID is already set.
 */
nuvo_return_t nuvo_pr_set_node_uuid(const uuid_t local_node_id);

/**
 * \brief Get the node uuid for local node
 *
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 * \retval -NUVO_ENOENT Local node UUID is not set.
 */
nuvo_return_t nuvo_pr_get_node_uuid(uuid_t local_node_id);

/**
 * \fn void nuvo_pr_enable();
 * \brief Tell the parcel router it can be fully functional.
 *
 * The parcel router should only become fully functional after it has
 * been fully initialized.  There are some configuration items that may
 * come only after a user API has completed.  This function is called
 * to tell the parcel router that it has been fully initialized and
 * can start operation.  Keep in mind, enabling may just wake up the
 * parcel router so that it can die.  Calling nuvo_pr_enable more than
 * once is not a problem.
 * The parcel router server thread will wait to start until the kontroller
 * has finished doing the initial node config.  Otherwise a remote node could
 * create a connection and start sending requests for devices that this node
 * should own but isn't aware of yet.
 * If enable_server is set, all pr threads will be enabled, including the
 * server thread.
 * \param enable_server If true to enable the parcel router server thread
 */
void nuvo_pr_enable(bool enable_server);

/**
 * \brief Shuts down the parcel router layer.
 *
 * This function shuts down the parcel router layer by terminating all
 * existing connections, ceasing to listen for future connections, stopping
 * network polling threads, and freeing all allocated memory.  Upper software
 * layers should already be shutdown before calling this function.
 */
void nuvo_pr_shutdown();

/**
 * \brief Finds and returns a struct nuvo_pr_node_desc for a node.
 *
 * This function searches the list of nodes for one matching the uuid in
 * \p node_id.  If found, the struct nuvo_pr_node_desc is locked and a pointer
 * to it is returned.  It is the caller's responsibility to release the mutex
 * lock of the struct nuvo_pr_node_desc when it is done being used.  The
 * caller should also avoid making calls into the parcel router layer
 * while the lock is held as it could potentially result in a deadlock.
 *
 * \param node_id The UUID of the node to find.
 * \returns A pointer to a struct nuvo_pr_node_desc for the matching node if
 * found.  Otherwise, returns NULL.
 */
struct nuvo_pr_node_desc *nuvo_pr_node_get_locked(const uuid_t node_id);

/**
 * \brief Inserts a new node record into the parcel router layer.
 *
 * This function is used to inform the parcel router layer about the details
 * of a node in the cluster.  The parcel router layer internally allocates a
 * struct nuvo_pr_node_desc to track this formation.
 *
 * \param node_id The UUID of the node to find.
 * \param address The IPv4 address of the node.
 * \param port The TCP port to connect to on the node.
 * \returns Zero or positive integer on success.  Negative integer on failure.
 * \retval -NUVO_EINVAL Address length was larger than NUVO_MAX_ADDR_LEN.
 * \retval -NUVO_EEXIST Node with this UUID already exists.
 * \retval -NUVO_ENOMEM Failed to allocate a local node structure.
 */
nuvo_return_t nuvo_pr_node_insert(const uuid_t node_id, const char address[], uint_fast16_t port);

/**
 * \brief Removes a node record from the parcel router layer.
 *
 * This function is used to remove a node record previously inserted by
 * nuvo_pr_node_insert.  Removing a node record will result in all connections
 * to that node being terminated, all outstanding requests being aborted, and
 * all device records for the node being removed.
 *
 * \param node_id The UUID of the node to be removed.
 * \returns Zero or positive integer on success.  Negative integer on failure.
 * \retval -NUVO_ENOENT Node with specified UUID not found.
 * \retval -NUVO_EINVAL Cannot remove the local node.
 */
nuvo_return_t nuvo_pr_node_remove(const uuid_t node_id);

/**
 * \brief Handle kontroller notification that the node init is complete
 *
 * This is what allows the pr server thread to start.  Once the node has been
 * told about all of it's devices and config when it's first brought up, the
 * pr server can start.  If the pr server starts before then, other nodes
 * can send requests for devices that this node has not yet been informed of.
 *
 * \param node_id The UUID of the node to be removed.
 * \param clear Used to clear the init done flag for testing
 * \returns Zero or positive integer on success.  Negative integer on failure.
 * \retval -NUVO_ENOENT Node with specified UUID not found.
 */
nuvo_return_t nuvo_pr_node_init_done(const uuid_t node_id, bool clear);

/**
 * \brief Searches for a device record with matching UUID and returns the node UUID if found.
 *
 * This function searches the parcel router layer's device list for a device
 * matching the UUID provided in \p dev_id.  If such a device is found, the
 * function will return success, and the UUID of the node the device is
 * associated with will be stored in the uuid_t pointed to by \p node_id.
 *
 * \param dev_id The UUID of the device to look for.
 * \param node_id A pointer to return the value of the node UUID for the
 * device.
 * \returns If a device is found, returns zero or a positive integer.  If no
 * device in the list matched the UUID, returns a negative integer.
 * \retval -NUVO_ENODEV Device not found.
 */
nuvo_return_t nuvo_pr_device_lookup(const uuid_t dev_id, uuid_t *node_id);

/**
 * \brief Checks if the device exists and is located on a remote node
 *
 * \param node_id The UUID of the node.
 * \returns true if the device exists and is remote.
 * \returns false if the device is not found, or is on the local node.
 */
bool nuvo_pr_is_device_remote(const uuid_t dev_id);

/**
 * \brief Updates which node is associated with a device.
 *
 * This function updates a device record to associate it with the node
 * identified by \p node_id.  For this function to succeed, there must be
 * valid node record for the node and a valid device record for the device.
 *
 * \param dev_id The UUID of the device to look for.
 * \param node_id The UUID of the new node to associate the device with.
 * \returns If the device record and node record are found, returns zero
 * or a positive integer.  If either the device record or node record are
 * missing, the return will be a negative integer.
 * \retval -NUVO_ENOENT Node entry not found.
 * \retval -NUVO_ENODEV Device not found.
 */
nuvo_return_t nuvo_pr_device_update(const uuid_t dev_id, const uuid_t node_id);

/**
 * \brief Inserts a new device record into the parcel router layer.
 *
 * This function inserts a new device record into the parcel router layer,
 * which effectively associates a device UUID with a node.  This allows the
 * parcel router layer to route requests for a particular device to the node
 * where the device resides.  Prior to associating a device with a node, the
 * parcel router layer must have had the node registered with
 * nuvo_pr_node_insert.  Invoking this function with an existing device will
 * result in a failure.  To update an existing device use the
 * nuvo_pr_device_update function instead.
 *
 * \param dev_id The UUID of the device to look for.
 * \param node_id The UUID of the node to associate the device with.
 * \returns Zero or a positive integer on success.  On failure, returns a
 * negative integer.
 * \retval -NUVO_ENOENT Node entry not found.
 * \retval -NUVO_EEXIST Device entry for UUID already exists.
 * \retval -NUVO_ENOMEM Cannot allocate a device record.
 */
nuvo_return_t nuvo_pr_device_insert(const uuid_t dev_id, const uuid_t node_id);

/**
 * \brief Removes a device record from the parcel router layer.
 *
 * This function removes a device to node association from the parcel router
 * layer that was previously associated by nuvo_pr_device_insert.
 *
 * \param dev_id The UUID of the device to look for.
 * \returns Zero or a positive integer on success.  On failure, returns a
 * negative integer.
 * \retval -NUVO_ENODEV Device not found.
 */
nuvo_return_t nuvo_pr_device_remove(const uuid_t dev_id);

/**
 * \brief Removes all device records associated with a node.
 *
 * This function removes all device records associated with the node
 * identified by \p node_id.  The node must have previously been registered
 * with nuvo_pr_node_insert.
 *
 * \param node_id The UUID of the node.
 * \returns Zero or a positive integer on success.  On failure, returns a
 * negative integer.
 * \retval -NUVO_ENOENT Node entry not found.
 */
nuvo_return_t nuvo_pr_device_remove_all(const uuid_t node_id);

/**
 * \brief Allocate a struct nuvo_io_request.
 *
 * This function attempts to allocate
 * a struct nuvo_io_request from the request pool in nuvo_pr.
 *
 * /returns If a struct nuvo_io_request was available and was allocated, a
 * pointer to it is returned.  Otherwise, NULL is returned.
 */
struct nuvo_io_request *nuvo_pr_client_req_alloc();

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
 * \param alloc The allocation request information.
 */
void nuvo_pr_client_req_alloc_cb(struct nuvo_pr_req_alloc *alloc);

/**
 * \brief Frees a struct nuvo_io_request.
 *
 * This function frees a struct
 * nuvo_io_request that was previously allocated by either nuvo_pr_req_alloc,
 * or nuvo_pr_req_alloc_cb.
 */
void nuvo_pr_client_req_free(struct nuvo_io_request *req);

/**
 * \brief Attempts to allocate a buffer.
 *
 * This function attempts to allocate a buffer from the pool in nuvo_pr.
 *
 * \returns If a buffer is available, returns a pointer to the allocated
 * buffer.  Otherwise, returns NULL.
 */
void *nuvo_pr_client_buf_alloc();

inline void nuvo_pr_buf_alloc_init_req(struct nuvo_pr_buf_alloc *alloc,
                                       struct nuvo_io_request   *req,
                                       union nuvo_tag            tag,
                                       void (*callback)(struct nuvo_pr_buf_alloc *))
{
    nuvo_dlnode_init(&alloc->list_node);
    alloc->req = req;
    alloc->tag = tag;
    alloc->callback = callback;
    alloc->buf_count = 0;
}

inline void nuvo_pr_buf_alloc_init_list(struct nuvo_pr_buf_alloc *alloc,
                                        void                    **list,
                                        uint_fast32_t             count,
                                        union nuvo_tag            tag,
                                        void (*callback)(struct nuvo_pr_buf_alloc *))
{
    nuvo_dlnode_init(&alloc->list_node);
    alloc->buf_list = list;
    alloc->tag = tag;
    alloc->callback = callback;
    alloc->buf_count = count;
}

/**
 * \brief Allocates buffers for a request with a callback completion.
 *
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
 * \param alloc A pointer to the allocation request information.
 */
void nuvo_pr_client_buf_alloc_batch(struct nuvo_pr_buf_alloc *alloc);

/**
 * \brief Free a buffer.
 *
 * This function frees a buffer that was previously allocated by either
 * nuvo_pr_buf_alloc or nubo_pr_buf_alloc_req.
 *
 * \param buf A pointer to the buffer to be freed.
 */
void nuvo_pr_client_buf_free(void *buf);

/**
 * \brief Frees a number of buffers for a request.
 *
 * This function frees a number of buffers that were previously allocated by
 * either nuvo_pr_buf_alloc or nuvo_pr_buf_alloc_req.  This function
 * accomplishes the same result as calling nuvo_pr_buf_free on the
 * req->rw.iovecs[n].iov_base pointers used by the request (i.e. the first
 * req->rw.block_count buffers).  However, this function is more efficient
 * than simply looping and calling nuvo_pr_buf_free and is thus prefered for
 * freeing a batch of buffers that was used for a particular request.
 *
 * \param req A pointer to the struct nuvo_io_request whose buffers to free.
 */
void nuvo_pr_client_buf_free_req(struct nuvo_io_request *req);
void nuvo_pr_client_buf_free_list(void **buf_list, uint_fast32_t count);


/**
 * \brief Submit a list of requests to the parcel router layer.
 *
 * This function submits a request to the parcel router layer.  The parcel
 * router layer will route the request and it's data to the node that can
 * execute the request, establishing network connections and transfering
 * the request and data over the network as necessary.  When requests are
 * completed, the parcel router layer will invoke their callbacks.  Note that
 * callbacks may be invoked immediately, or be deferred and invoked by another
 * thread at a later time.  Before submitting requests to this function, the
 * caller must ensure that it is safe to invoke the callbacks for the requests.
 *
 * \param submit_list A pointer to a struct nuvo_dlist containing the requests
 * to submit.
 */
void nuvo_pr_submit(struct nuvo_dlist *submit_list);

inline void nuvo_pr_submit_req(struct nuvo_io_request *req)
{
    struct nuvo_dlist submit_list;

    nuvo_dlist_init(&submit_list);
    nuvo_dlist_insert_tail(&submit_list, &req->list_node);
    nuvo_pr_submit(&submit_list);
}

/**
 * \brief Notify the parcel router layer of a request completion.
 *
 * This function is to be invoked by the parcel manager when a request that
 * was previously submitted to nuvo_pm_submit has completed.
 *
 * \param req A pointer to the request that completed.
 */
void nuvo_pr_complete(struct nuvo_io_request *req);

void nuvo_pm_submit(struct nuvo_dlist *submit_list);

/**
 * Currently this is called by a debug trigger.  When kontroller is ready,
 * this will be triggered by an api the kontroller calls when it is done with
 * initial node bring up configuration.
 */
void nuvo_pr_kontroller_config_done(bool is_done);

/**
 * Set the callback function to notify the volume when parcels become
 * unreachable/reachable due to node connection failure/recovery.
 */
void nuvo_pr_set_vol_notify_fp(nuvo_return_t
                               (*vol_notify_fp)(const uuid_t, uuid_t,
                                                enum nuvo_pr_parcel_status));

/**
 * \brief TEST ONLY - Log some pr stats, useful for functional tests.
 */
void nuvo_pr_log_stats(void);

/**
 * \brief TEST ONLY - If not already allocated, allocates mem for test_fi_info
 *
 * \returns pointer to test_fi_info in nuvo_pr
 */
struct test_fi_info *nuvo_pr_get_test_fi(void);
