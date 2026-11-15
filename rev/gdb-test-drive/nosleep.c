// nosleep.c - LD_PRELOAD hook to bypass sleep() delay loop
unsigned int sleep(unsigned int s) {
    return 0;
}
