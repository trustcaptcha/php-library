<?php

class AesEncryption {
    public static function decryptToString(string $key, string $encryptedText): string {
        $decoded = base64_decode($encryptedText);
        $iv = substr($decoded, 0, 16);
        $cipherText = substr($decoded, 16);
        $decrypted = openssl_decrypt($cipherText, 'aes-256-cbc', $key, 0, $iv);
        if ($decrypted === false) {
            throw new Exception("Decryption failed");
        }
        return $decrypted;
    }

    public static function toAesSecretKey(string $keyStringBase64Encoded): string {
        return base64_decode($keyStringBase64Encoded);
    }
}

