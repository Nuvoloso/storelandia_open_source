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
 * @file replay.h
 * @brief functions for replay required by the logger
 *
 */
#pragma once
void read_segment_digest(struct nuvo_logger *logger, struct logger_segment *log_segment);
void segment_read_complete(struct nuvo_io_request *io_req);
void do_replay(struct nuvo_logger *logger);
void free_replay_req(struct nuvo_logger *logger, struct nuvo_log_request *log_req);

bool process_segment_open_queue(struct nuvo_logger *logger);
bool open_segment(struct nuvo_logger *logger, struct nuvo_segment *segment);
void segment_io_submit(struct segment_io_req *seg_req, struct nuvo_io_request *io_req);
void segment_buf_alloc(struct nuvo_pr_req_alloc *req_alloc);
void close_segment(struct nuvo_logger *logger, struct logger_segment *log_segment, bool write_digest);

bool segment_digest_verify(struct nuvo_segment_digest *digest, nuvo_hash_t *block_hashes, uint32_t digest_len);
bool segments_need_replay(struct nuvo_logger *logger);
