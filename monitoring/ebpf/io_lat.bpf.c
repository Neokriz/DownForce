// io_lat.bpf.c
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef __always_inline
#define __always_inline __attribute__((always_inline)) inline
#endif

// -------------------- histogram config --------------------
#define LOG2_SLOTS   64
#define SUB_BUCKETS  8
#define HIST_SLOTS   (LOG2_SLOTS * SUB_BUCKETS)  // 512

// -------------------- config --------------------
struct cfg {
    __u32 target_dev;  // encoded dev_t = (major<<20) | minor
};

// -------------------- per-request timestamps --------------------
struct ts {
    __u64 insert_ns;   // optional
    __u64 issue_ns;    // required
    bool is_write;     // 방향 저장
};

/* ---------------- maps ---------------- */

// cfg_map[0] = struct cfg { target_dev = enc }
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cfg);
} cfg_map SEC(".maps");

// inflight timestamps keyed by rq pointer
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, __u64);   // (u64)rq
    __type(value, struct ts);
} inflight SEC(".maps");

// histograms (log2 + sub-buckets) - Read/Write 분리
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, HIST_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} hist_total_r_us SEC(".maps"),
  hist_total_w_us SEC(".maps"),
  hist_wait_r_us SEC(".maps"),   // 소프트웨어 큐 대기 시간
  hist_wait_w_us SEC(".maps"),
  hist_dev_r_us SEC(".maps"),    // 장치 처리 시간 (SQ 포함)
  hist_dev_w_us SEC(".maps"),
  hist_dev_r_us_mon SEC(".maps"), // 모니터링 전용
  hist_dev_w_us_mon SEC(".maps"); // 모니터링 전용

// 실시간 inflight 카운트 (장치 내에 머무는 요청 수) - 글로벌 ARRAY로 변경
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} inflight_cnt SEC(".maps");

// 지연 시간 합계를 저장할 맵 (평균 계산용)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lat_wait_r_sum SEC(".maps"),
  lat_wait_w_sum SEC(".maps"),
  lat_dev_r_sum SEC(".maps"),
  lat_dev_w_sum SEC(".maps");

// program hit counters: 0=insert,1=issue,2=complete,3=missed
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} prog_hits SEC(".maps");

static __always_inline void hit(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&prog_hits, &idx);
    if (v)
        (*v)++;
}

/* ---------------- helpers ---------------- */

static __always_inline __u32 log2_msb_u64(__u64 v)
{
    if (v == 0)
        return 0;

    __u32 r = 0;
    if (v >> 32) { v >>= 32; r += 32; }
    if (v >> 16) { v >>= 16; r += 16; }
    if (v >> 8)  { v >>= 8;  r += 8;  }
    if (v >> 4)  { v >>= 4;  r += 4;  }
    if (v >> 2)  { v >>= 2;  r += 2;  }
    if (v >> 1)  {           r += 1;  }

    if (r >= LOG2_SLOTS)
        r = LOG2_SLOTS - 1;
    return r;
}

// Convert microseconds -> histogram index (log2 + SUB_BUCKETS)
// idx = msb*SUB_BUCKETS + sub, in [0, 511]
static __always_inline __u32 hist_idx_us(__u64 us)
{
    if (us == 0)
        return 0;

    __u32 msb = log2_msb_u64(us);          // 0..63
    __u64 base = 1ULL << msb;              // [base, 2*base)
    __u64 off  = us - base;                // 0..base-1

    // sub = floor(off * SUB_BUCKETS / base)
    __u32 sub = (__u32)((off * SUB_BUCKETS) / base);
    if (sub >= SUB_BUCKETS)
        sub = SUB_BUCKETS - 1;

    __u32 idx = msb * SUB_BUCKETS + sub;
    if (idx >= HIST_SLOTS)
        idx = HIST_SLOTS - 1;

    return idx;
}

static __always_inline void hist_inc(void *map, __u64 us)
{
    __u32 idx = hist_idx_us(us);
    __u64 *v = bpf_map_lookup_elem(map, &idx);
    if (v)
        (*v)++;
}

static __always_inline void sum_inc(void *map, __u64 us)
{
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(map, &key);
    if (v)
        (*v) += us;
}

static __always_inline bool is_write_rq(struct request *rq)
{
    // REQ_OP_MASK는 보통 0xff입니다. 
    // 하위 8비트가 operation을 나타내며, READ=0, WRITE=1입니다.
    __u32 op = BPF_CORE_READ(rq, cmd_flags) & 0xff;
    return op == 1 || op == 7 || op == 9; // WRITE, WRITE_SAME, WRITE_ZEROES 등
}

// rq->rq_disk 기반 dev encoding
static __always_inline __u32 rq_encoded_dev(const struct request *rq)
{
    struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);
    
    // rq_disk가 NULL이면 request_queue에서 가져오기 시도
    if (!disk) {
        disk = BPF_CORE_READ(rq, q, disk);
    }
    
    if (!disk)
        return 0;

    __u32 major = BPF_CORE_READ(disk, major);
    __u32 first_minor = BPF_CORE_READ(disk, first_minor);

    return ((major & 0xfff) << 20) | (first_minor & 0xfffff);
}

static __always_inline bool dev_match_rq(const struct request *rq)
{
    __u32 key0 = 0;
    struct cfg *c = bpf_map_lookup_elem(&cfg_map, &key0);
    if (!c)
        return false;

    if (c->target_dev == 0)
        return true;

    __u32 dev = rq_encoded_dev(rq);
    return dev == c->target_dev;
}

/* ---------------- tp_btf programs ----------------
 *
 * 커널 BTF에서 확인된 시그니처:
 *   btf_trace_block_rq_insert(void *, struct request *)
 *   btf_trace_block_rq_issue(void *, struct request *)
 *   btf_trace_block_rq_complete(void *, struct request *, int, unsigned int)
 *
 * BPF_PROG()를 쓰면 첫 번째 ctx 인자는 매크로가 자동으로 붙여준다.
 * 따라서 인자 목록에는 "struct request *rq, ..."만 적으면 된다.
 */

// 큐에 명시적으로 삽입되는 경우 (Slow Path)
SEC("tp_btf/block_rq_insert")
int BPF_PROG(tp_insert, struct request *rq)
{
    if (!rq || !dev_match_rq(rq))
        return 0;

    hit(0); // Req 카운트
    __u64 key = (__u64)rq;
    // rq->start_time_ns를 사용하므로 별도의 시간 기록 없이 존재 여부만 확인하거나 
    // 나중에 issue에서 처리하도록 함. 여기서는 Req 카운트만 올림.
    
    struct ts *t = bpf_map_lookup_elem(&inflight, &key);
    if (!t) {
        struct ts nt = {};
        nt.insert_ns = BPF_CORE_READ(rq, start_time_ns);
        nt.is_write = is_write_rq(rq);
        bpf_map_update_elem(&inflight, &key, &nt, BPF_ANY);
    }
    return 0;
}

// issue: dev_us 시작점 + wait_us 계산
SEC("tp_btf/block_rq_issue")
int BPF_PROG(tp_issue, struct request *rq)
{
    if (!rq || !dev_match_rq(rq))
        return 0;

    hit(1); // Iss 카운트
    __u64 key = (__u64)rq;
    __u64 now = bpf_ktime_get_ns();
    __u64 start_ns = BPF_CORE_READ(rq, start_time_ns);

    struct ts *t = bpf_map_lookup_elem(&inflight, &key);
    if (!t) {
        // Fast Path: insert 없이 바로 issue로 온 경우
        hit(0); // 여기서 Req 카운트를 대신 올림
        struct ts nt = {};
        nt.insert_ns = start_ns;
        nt.issue_ns = now;
        nt.is_write = is_write_rq(rq);
        bpf_map_update_elem(&inflight, &key, &nt, BPF_ANY);
    } else {
        if (t->issue_ns == 0)
            t->issue_ns = now;
        t->insert_ns = start_ns; // 항상 커널의 정확한 시작 시간 사용
    }

    // Inflight 카운트 증가 (원자적 연산)
    __u32 k0 = 0;
    __u64 *cnt = bpf_map_lookup_elem(&inflight_cnt, &k0);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(tp_complete, struct request *rq, int error, unsigned int nr_bytes)
{
    if (!rq || !dev_match_rq(rq))
        return 0;

    hit(2); // Match된 디바이스의 Complete 히트
    
    __u64 key = (__u64)rq;
    struct ts *t = bpf_map_lookup_elem(&inflight, &key);
    if (!t) {
        hit(3); // Missed! 시작점을 찾을 수 없음
        return 0;
    }

    __u64 now = bpf_ktime_get_ns();

    // Device Latency 기록
    if (t->issue_ns) {
        __u64 d_us = (now - t->issue_ns) / 1000;
        if (t->is_write) {
            hist_inc(&hist_dev_w_us, d_us);
            hist_inc(&hist_dev_w_us_mon, d_us);
            sum_inc(&lat_dev_w_sum, d_us);
        } else {
            hist_inc(&hist_dev_r_us, d_us);
            hist_inc(&hist_dev_r_us_mon, d_us);
            sum_inc(&lat_dev_r_sum, d_us);
        }
    }

    // Wait Latency 기록 (시점 정합성을 위해 complete에서 기록)
    if (t->insert_ns && t->issue_ns) {
        __u64 q_us = (t->issue_ns - t->insert_ns) / 1000;
        if (t->is_write) {
            hist_inc(&hist_wait_w_us, q_us);
            sum_inc(&lat_wait_w_sum, q_us);
        } else {
            hist_inc(&hist_wait_r_us, q_us);
            sum_inc(&lat_wait_r_sum, q_us);
        }
    }

    // Inflight 카운트 감소 (원자적 연산)
    __u32 k0 = 0;
    __u64 *cnt = bpf_map_lookup_elem(&inflight_cnt, &k0);
    if (cnt)
        __sync_fetch_and_add(cnt, -1);

    bpf_map_delete_elem(&inflight, &key);
    return 0;
}
