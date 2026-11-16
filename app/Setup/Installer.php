<?php

namespace App\Setup;

use App\Services\Shell;
use App\Setup\Steps\AppArmor;
use App\Setup\Steps\Environment;
use App\Setup\Steps\FirewallRepair;
use App\Setup\Steps\Forwarding;
use App\Setup\Steps\Health;
use App\Setup\Steps\Helper;
use App\Setup\Steps\Packages;
use App\Setup\Steps\Permissions;
use App\Setup\Steps\PfAnchors;
use App\Setup\Steps\Policy;
use App\Setup\Steps\Server;
use App\Setup\Steps\Shortcut;
use App\Setup\Steps\Sudoers;
use App\Setup\Steps\WebUser;

/**
 * The steps of `wg:install`, in order, and what they share: the context and its saved answers.
 */
class Installer
{
    /** Answers saved in .env, so re-runs and `wg:update` know how this server was set up. */
    public const SAVED = [
        'web_user' => 'WGLA_WEB_USER',
        'forward' => 'WGLA_FORWARD',
        'tls' => 'WGLA_SERVER_TLS',
        'port' => 'WGLA_SERVER_PORT',
        'domain' => 'WGLA_SERVER_DOMAIN',
        'cert' => 'WGLA_SERVER_CERT',
        'key' => 'WGLA_SERVER_KEY',
        'bind' => 'WGLA_SERVER_BIND',
        'admin_port' => 'WGLA_SERVER_ADMIN_PORT',
        'allow_default_route' => 'WGLA_ALLOW_DEFAULT_ROUTE',
        'allow_own_networks' => 'WGLA_ALLOW_OWN_NETWORKS',
    ];

    /**
     * @param  string|null  $helperPath  where the root helper is installed (default: config('wireguard.helper'))
     */
    public function __construct(protected Shell $shell, protected ?string $helperPath = null) {}

    /** @return list<Step> */
    public function steps(): array
    {
        $server = new Server($this->shell);

        return [
            new Packages($this->shell),
            new WebUser($this->shell),
            new Permissions($this->shell),
            new Environment($this->shell),
            new Forwarding($this->shell),
            new PfAnchors($this->shell),
            new Helper($this->shell),
            new Sudoers($this->shell),
            new Policy($this->shell),
            new AppArmor($this->shell),
            new FirewallRepair($this->shell),
            new Shortcut($this->shell),
            $server,
            new Health($this->shell, $server),
        ];
    }

    /**
     * @param  array<string, mixed>  $given  answers from command-line options; they win over saved ones
     */
    public function context(array $given = [], ?string $appPath = null, string $root = ''): Context
    {
        $appPath ??= base_path();
        $user = $this->shell->tryRun('id -un') ?: get_current_user();

        $ctx = new Context(
            os: PHP_OS_FAMILY === 'Darwin' ? 'mac' : 'linux',
            appPath: $appPath,
            deployUser: $user,
            deployGroup: $this->shell->tryRun('id -gn') ?: $user,
            php: PHP_BINARY,
            helperPath: $this->helperPath ?? (string) config('wireguard.helper'),
            bundledHelper: "{$appPath}/bin/wgla-helper",
            root: $root,
        );

        $env = new EnvFile($ctx->app('.env'));
        foreach (self::SAVED as $answer => $key) {
            $value = $env->get($key);
            if ($value !== null && $value !== '') {
                $ctx->answers[$answer] = $value;
            }
        }
        foreach ($given as $answer => $value) {
            if ($value !== null) {
                $ctx->answers[$answer] = $value;
            }
        }

        // Derived here, not only by the web-user step: wg:update and `wg:install --step=` don't
        // run that step, and the service unit and .env need the group all the same
        if (($web = $ctx->answer('web_user')) !== null) {
            $ctx->answers['web_group'] = $this->shell->tryRun('id -gn :user', ['user' => (string) $web]) ?: (string) $web;
        }

        return $ctx;
    }

    /** Save the answers into .env once it exists (the environment step creates it). */
    public function save(Context $ctx): void
    {
        $env = new EnvFile($ctx->app('.env'));
        if (! $env->exists()) {
            return;
        }

        foreach (self::SAVED as $answer => $key) {
            $value = $ctx->answer($answer);
            if ($value !== null) {
                $env->set($key, is_bool($value) ? ($value ? 'true' : 'false') : (string) $value);
            }
        }
    }

    /**
     * Make sure sudo works for the checks and fixes: passwordless as it is, or by asking for the
     * password once. Never `sudo -v` first: it asks unless every sudoers entry of the user has
     * NOPASSWD (verifypw defaults to `all`), also where no command needs a password.
     */
    public function sudoReady(bool $interactive): bool
    {
        return $this->shell->tryRun('sudo -n true') !== null
            || ($interactive && $this->shell->interactive('sudo -v') === 0);
    }

    public function run(Action $action, Context $ctx): bool
    {
        if ($action->callback !== null) {
            ($action->callback)($ctx);

            return true;
        }

        return $this->shell->interactive((string) $action->command) === 0;
    }
}
