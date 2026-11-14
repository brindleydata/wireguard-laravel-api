<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\Question;
use App\Setup\Step;

class WebUser extends Step
{
    public function key(): string
    {
        return 'web-user';
    }

    public function title(): string
    {
        return 'Web server user';
    }

    public function questions(Context $ctx): array
    {
        return [new Question(
            key: 'web_user',
            label: 'Which user should run the API?',
            // macOS is a development target: the developer runs the server themselves
            default: fn (Context $ctx) => $ctx->isMac() ? $ctx->deployUser : 'www-data',
            validate: fn ($value) => match (true) {
                ! preg_match('/^[a-z_][a-z0-9_-]*$/i', (string) $value) => 'Not a valid user name.',
                $value === 'root' => 'The API must not run as root: that is what the root helper is for.',
                default => null,
            },
            hint: 'It gets sudo for the root helper only. Owner of the code stays: '.$ctx->deployUser,
        )];
    }

    public function after(Context $ctx): void
    {
        $ctx->answers['web_group'] = $this->shell->tryRun('id -gn :user', ['user' => $ctx->webUser()]) ?: $ctx->webUser();
    }

    public function check(Context $ctx): array
    {
        return $this->shell->tryRun('id -u :user', ['user' => $ctx->webUser()]) === null
            ? ["User {$ctx->webUser()} doesn't exist"]
            : [];
    }

    public function plan(Context $ctx): array
    {
        return $ctx->isMac() ? [] : [Action::command(
            'Create a system user without a login',
            'sudo useradd --system --no-create-home --shell /usr/sbin/nologin '.self::q($ctx->webUser()),
        )];
    }

    public function manual(Context $ctx): string
    {
        return "Create the user {$ctx->webUser()}, or choose an existing one.";
    }
}
