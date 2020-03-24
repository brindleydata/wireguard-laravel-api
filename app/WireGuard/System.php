<?php

namespace App\WireGuard;

class System
{
    public static function exec($command): array
    {
        \exec($command, $output, $ret);
        if ($ret) {
            $output = implode("\n", $output);
            throw new Exception("System call failed.\nCommand: {$command}\n\n{$output}");
        }

        return $output;
    }

    public static function shot($command): ?string
    {
        $ret = self::exec($command);
        if (!is_array($ret)) {
            throw new Exception("System shot failed, exec() failed,\nCommand: {$command}\n\n{$output}");
        }

        return $ret[0] ?? null;
    }
}
