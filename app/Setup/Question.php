<?php

namespace App\Setup;

use Closure;

/**
 * Something a step needs to know. Answers land in Context::$answers under $key.
 */
final class Question
{
    /**
     * @param  string  $type  text, select or confirm
     * @param  mixed  $default  a value, or fn (Context): mixed
     * @param  array<string, string>  $options  select: value => label
     * @param  Closure|null  $when  fn (Context): bool; the question is skipped when false
     * @param  Closure|null  $validate  fn (mixed $value, Context): ?string error
     * @param  Closure|null  $warning  fn (mixed $value, Context): ?string shown after answering
     */
    public function __construct(
        public readonly string $key,
        public readonly string $label,
        public readonly string $type = 'text',
        public readonly mixed $default = null,
        public readonly array $options = [],
        public readonly ?Closure $when = null,
        public readonly ?Closure $validate = null,
        public readonly ?Closure $warning = null,
        public readonly string $hint = '',
    ) {}

    public function applies(Context $ctx): bool
    {
        return $this->when === null || ($this->when)($ctx);
    }

    public function defaultFor(Context $ctx): mixed
    {
        return $this->default instanceof Closure ? ($this->default)($ctx) : $this->default;
    }

    public function error(mixed $value, Context $ctx): ?string
    {
        return $this->validate === null ? null : ($this->validate)($value, $ctx);
    }

    public function warningFor(mixed $value, Context $ctx): ?string
    {
        return $this->warning === null ? null : ($this->warning)($value, $ctx);
    }
}
