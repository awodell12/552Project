PCM * m = PCM::getInstance();

// program counters, and on a failure just exit

if (m->program() != PCM::Success) return;

SystemCounterState before_sstate = getSystemCounterState();

    spectre.main(); 

SystemCounterState after_sstate = getSystemCounterState();

  cout << "Instructions per clock:" << getIPC(before_sstate,after_sstate)

  << "L3 cache hit ratio:" << getL3CacheHitRatio(before_sstate,after_sstate)

  << "Bytes read:" << getBytesReadFromMC(before_sstate,after_sstate)

  << [and so on]...