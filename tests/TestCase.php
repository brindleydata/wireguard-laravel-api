<?php

namespace Tests;

use App\Services\Server;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // What a process keeps between requests: each test starts like a new one
        Server::forgetHealth();
    }
}
