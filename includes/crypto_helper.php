<?php

declare(strict_types=1);

function getMasterKey(): string
{

    $secret = 'CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_KEY_FOR_SEPMS_ADMIN_PRINTING';

    return hash('sha256', $secret, true);
}

function encryptAdminKey(string $plainKey): array
{
    $method = 'aes-256-cbc';
    $ivLength = openssl_cipher_iv_length($method);
    $iv = random_bytes($ivLength);

    $cipher = openssl_encrypt(
        $plainKey,
        $method,
        getMasterKey(),
        OPENSSL_RAW_DATA,
        $iv
    );

    if ($cipher === false) {
        throw new RuntimeException('Failed to encrypt admin key.');
    }

    return [
        'cipher' => base64_encode($cipher),
        'iv' => base64_encode($iv),
    ];
}

function decryptAdminKey(string $cipherText, string $ivText): string
{
    $method = 'aes-256-cbc';

    $cipher = base64_decode($cipherText, true);
    $iv = base64_decode($ivText, true);

    if ($cipher === false || $iv === false) {
        throw new RuntimeException('Invalid admin key data.');
    }

    $plainKey = openssl_decrypt(
        $cipher,
        $method,
        getMasterKey(),
        OPENSSL_RAW_DATA,
        $iv
    );

    if ($plainKey === false) {
        throw new RuntimeException('Failed to decrypt admin key.');
    }

    return $plainKey;
}
