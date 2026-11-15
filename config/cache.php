<?php

// The framework's cache config, but files by default: there is no database. The rate limit on
// wrong API keys keeps its counts here, which every Octane worker has to share.
return [
    'default' => env('CACHE_STORE', 'file'),
];
