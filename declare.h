static unsigned int packetCounter, sampleCounter, errorLearnCounter, errorFilterCounter;
static unsigned int hcfState;
static int receivedHopCount, flag;
unsigned int i, mid, initialTTL;
unsigned long start_time, total_time, errorAvg, learnThreshold, filterThreshold;
unsigned int initialTTLSet[6] = {30, 32, 60, 64, 128, 255};
