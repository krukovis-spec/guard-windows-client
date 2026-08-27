using System;
using System.Collections.Generic;

namespace Guard
{
    public class UpdateFor
    {
        public bool UpdateApplied { get; set; } = true;
        public bool SyncStatUpdate { get; set; } = false;
        public bool Parameters { get; set; } = false; // needs reconnect
        public bool Rules { get; set; } = false; // needs reconnect
        public bool Cats { get; set; } = false; // needs reconnect
        public bool Ips { get; set; } = false; // needs reconnect
        public bool Presets { get; set; } = false; // needs reconnect
        public bool RestrictedCats { get; set; } = false; // needs reconnect
        public int ErrorCount { get; set; } = 0;
    }
}
