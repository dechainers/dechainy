#ifdef TEST_SWAP
BPF_TABLE("array", int, int, MAP_SWAP, 1)__attributes__((SWAP));
#endif
#ifdef TEST_EXPORT
BPF_TABLE("array", int, int, MAP_EXPORT, 1)__attributes__((EXPORT));
#endif
#ifdef TEST_EMPTY
BPF_TABLE("array", int, int, MAP_EMPTY, 1)__attributes__((EMPTY));
#endif
#ifdef TEST_ALL_FEATURES
BPF_TABLE("array", int, int, MAP_ALL, 1)__attributes__((SWAP, EXPORT, EMPTY));
#endif

static __always_inline
int handler(struct CTXTYPE *ctx, struct pkt_metadata *md) {
#ifdef TEST_LOG
    dp_log(INFO, "Ciao from Data Plane %d", CUSTOM_VARIABLE);
#endif
#ifdef TEST_CONTROL_PLANE
    return pkt_to_controller(ctx, md);
#endif
#ifdef TEST_TIME_EPOCH
    u64 ttime = get_time_epoch();
#endif
#ifdef TEST_FIRST_BIT
    int pos = first_bit_set_pos(2);
#endif
#ifdef TEST_DROP
    return DROP;
#endif
#ifdef TEST_PASS
    return PASS;
#endif
#ifdef TEST_REDIRECT
    return REDIRECT(lo);
#endif

    return PASS;
}