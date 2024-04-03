<?php

namespace Trustcaptcha;

use Exception;

class AesEncryption {

    public static function decryptToString(string $key, string $encryptedText): string {

        $decodedKey = self::toAesSecretKey($key);
        $decodedEncryptedText = base64_decode($encryptedText, true);
        if ($decodedEncryptedText === false) {
            throw new Exception("Base64 decoding of encrypted text failed");
        }

        $iv = substr($decodedEncryptedText, 0, 16);
        $cipherText = substr($decodedEncryptedText, 16);
        $decryptedText = openssl_decrypt($cipherText, 'aes-256-cbc', $decodedKey, OPENSSL_RAW_DATA, $iv);
        if ($decryptedText === false) {
            throw new Exception("Decryption failed: " . openssl_error_string());
        }

        return $decryptedText;
    }

    private static function toAesSecretKey(string $keyStringBase64Encoded): string {
        return base64_decode($keyStringBase64Encoded, true);
    }
}
