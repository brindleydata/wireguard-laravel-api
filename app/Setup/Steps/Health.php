<?php

namespace App\Setup\Steps;

use App\Services\Shell;
use App\Setup\Context;
use App\Setup\Step;

/**
 * The end-to-end check: the web user can run the helper through sudo, and (on Linux) the API
 * answers and reports the helper as ok.
 */
class Health extends Step
{
    public function __construct(Shell $shell, protected Server $server)
    {
        parent::__construct($shell);
    }

    public function key(): string
    {
        return 'health';
    }

    public function title(): string
    {
        return 'Health check';
    }

    public function check(Context $ctx): array
    {
        $problems = [];

        $version = $ctx->separateWebUser()
            ? $this->asRoot('-u :user sudo -n :helper version', ['user' => $ctx->webUser(), 'helper' => $ctx->helperPath])
            : $this->shell->tryRun('sudo -n :helper version', ['helper' => $ctx->helperPath]);
        if ($version === null || ! preg_match('/^VERSION='.preg_quote($version, '/').'$/m', (string) file_get_contents($ctx->bundledHelper))) {
            $problems[] = "{$ctx->webUser()} can't run the root helper through sudo";
        }

        if ($this->server->applies($ctx)) {
            [$url, $options] = $this->server->localUrl($ctx);
            $state = null;
            for ($attempt = 0; $attempt < 15 && $state === null; $attempt++) {
                $body = $this->shell->tryRun("curl -s --fail --max-time 3 {$options} :url", ['url' => "{$url}/status"]);
                $state = $body === null ? null : (json_decode($body, true)['helper']['state'] ?? 'unknown');
                if ($state === null && $attempt < 14) {
                    sleep(1);
                }
            }

            if ($state === null) {
                $problems[] = "The API doesn't answer at {$url}";
            } elseif ($state !== 'ok') {
                $problems[] = "The API reports the root helper as: {$state}";
            }
        }

        return $problems;
    }

    public function plan(Context $ctx): array
    {
        return [];
    }

    public function manual(Context $ctx): string
    {
        return $this->server->applies($ctx)
            ? 'See the service log: sudo journalctl -u wgla -n 50 --no-pager. Then run php artisan wg:install again.'
            : 'Run php artisan wg:install again and fix the steps it reports.';
    }
}
