<?php

return [
    /*
     * The framework's default "local" disk is served over HTTP (GET and PUT /storage/{path}, by
     * signed URL). This app serves no files, and only /health is public: turn that off.
     */
    'disks' => [
        'local' => [
            'driver' => 'local',
            'root' => storage_path('app/private'),
            'serve' => false,
            'throw' => false,
            'report' => false,
        ],
    ],
];
