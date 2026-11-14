<?php

namespace App\Services;

use chillerlan\QRCode\Common\EccLevel;
use chillerlan\QRCode\Output\QRMarkupSVG;
use chillerlan\QRCode\QRCode as Generator;
use chillerlan\QRCode\QROptions;

/**
 * QR codes of client configs, which the WireGuard apps can scan. Dark modules on a light
 * background in both forms, as scanners expect, whatever the page or terminal colors are.
 */
class QrCode
{
    /** An SVG image with a white background (also on a dark page). */
    public function svg(string $data): string
    {
        $svg = (new Generator(new QROptions([
            'eccLevel' => EccLevel::L,
            'outputInterface' => QRMarkupSVG::class,
            'outputBase64' => false,
            'drawLightModules' => false,
        ])))->render($data);

        // The SVG output has no background of its own: put one behind the modules
        return preg_replace('/(<svg\b[^>]*>)/', '$1<rect width="100%" height="100%" fill="#ffffff"/>', $svg, 1);
    }

    /**
     * For a terminal: two rows of modules per line in upper half blocks, colored with ANSI codes
     * (black and bright white foreground/background).
     */
    public function terminal(string $data): string
    {
        $rows = (new Generator(new QROptions(['eccLevel' => EccLevel::L, 'quietzoneSize' => 2])))
            ->addByteSegment($data)
            ->getQRMatrix()
            ->getBooleanMatrix();

        $lines = [];
        for ($y = 0; $y < count($rows); $y += 2) {
            $line = '';
            $color = null;
            foreach ($rows[$y] as $x => $top) {
                // The upper half is the foreground, the lower half the background
                $next = "\e[".($top ? '30' : '97').';'.(($rows[$y + 1][$x] ?? false) ? '40' : '107').'m';
                $line .= ($next === $color ? '' : $next).'▀';
                $color = $next;
            }
            $lines[] = $line."\e[0m";
        }

        return implode("\n", $lines);
    }
}
