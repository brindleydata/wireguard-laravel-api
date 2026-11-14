<?php

use App\Services\QrCode;
use chillerlan\QRCode\Common\EccLevel;
use chillerlan\QRCode\Output\QRGdImagePNG;
use chillerlan\QRCode\QRCode as Generator;
use chillerlan\QRCode\QROptions;

/*
 * QR codes of client configs: they must decode to the exact config.
 */

const QR_TEST_CONFIG = "[Interface]\nPrivateKey = qE8+3UtPrZNyenysscMK1oUKwCcyO9ea5h17tpNM9FE=\nAddress = 10.0.0.2/32, fd12::2/128\nDNS = 8.8.8.8\n\n"
    ."[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nPresharedKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n"
    ."AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.example.test:51820\nPersistentKeepalive = 25";

it('renders an SVG image with a white background', function () {
    $svg = (new QrCode)->svg(QR_TEST_CONFIG);

    expect($svg)->toStartWith('<?xml')
        ->toMatch('/<svg [^>]*><rect width="100%" height="100%" fill="#ffffff"\/>\s*<path [^>]*fill="#000"/');
});

it('draws exactly the QR matrix in the terminal, two rows per line', function () {
    $lines = explode("\n", (new QrCode)->terminal(QR_TEST_CONFIG));
    $expected = (new Generator(new QROptions(['eccLevel' => EccLevel::L, 'quietzoneSize' => 2])))
        ->addByteSegment(QR_TEST_CONFIG)->getQRMatrix()->getBooleanMatrix();

    // Read the colors back: foreground = upper module, background = lower module
    $rows = [];
    foreach ($lines as $line) {
        preg_match_all('/(?:\e\[(\d+);(\d+)m)?▀/u', $line, $cells, PREG_SET_ORDER);
        [$top, $bottom] = [[], []];
        foreach ($cells as $cell) {
            if (($cell[1] ?? '') !== '') {
                [$fg, $bg] = [$cell[1] === '30', $cell[2] === '40'];
            }
            $top[] = $fg;
            $bottom[] = $bg;
        }
        $rows[] = $top;
        $rows[] = $bottom;
    }

    expect(array_slice($rows, 0, count($expected)))->toBe($expected)
        ->and(end($lines))->toEndWith("\e[0m");
});

it('encodes the config so a scanner reads it back', function () {
    if (! extension_loaded('gd')) {
        $this->markTestSkipped('needs GD to rasterize and decode');
    }
    $png = (new Generator(new QROptions(['eccLevel' => EccLevel::L, 'outputInterface' => QRGdImagePNG::class, 'outputBase64' => false])))->render(QR_TEST_CONFIG);

    expect((string) (new Generator)->readFromBlob($png))->toBe(QR_TEST_CONFIG);
});
