<?php

namespace App\WireGuard;

use function exec;

class System
{
    /**
     * @param $command
     * @return array
     * @throws Exception
     */
    public static function exec($command): array
    {
        exec($command, $output, $ret);
        if ($ret) {
            $output = implode("\n", $output);
            throw new Exception("System call failed.\nCommand: {$command}\n\n{$output}");
        }

        return $output;
    }

    /**
     * @param $command
     * @return string|null
     * @throws Exception
     */
    public static function shot($command): ?string
    {
        $ret = self::exec($command);

        return $ret[0] ?? null;
    }
}
