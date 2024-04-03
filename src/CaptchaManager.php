<?php

namespace Trustcaptcha;

use Exception;

require_once 'model/VerificationToken.php';
require_once 'model/VerificationResult.php';
require_once 'AesEncryption.php';

class CaptchaManager {

    public static function getVerificationResult(string $base64secretKey, string $base64verificationToken): VerificationResult {
        $verificationToken = self::getVerificationToken($base64verificationToken);
        $accessToken = AesEncryption::decryptToString($base64secretKey, $verificationToken->encryptedAccessToken);
        $urlAsString = "{$verificationToken->apiEndpoint}/verifications/{$verificationToken->verificationId}/assessments?accessToken={$accessToken}";

        $response = file_get_contents($urlAsString);
        if ($response === false) {
            throw new Exception("Failed to retrieve verification result");
        }
        return new VerificationResult($response);
    }

    private static function getVerificationToken(string $verificationToken): VerificationToken {
        $decodedVerificationToken = base64_decode($verificationToken);
        $data = json_decode($decodedVerificationToken);
        return new VerificationToken($data->apiEndpoint, $data->verificationId, $data->encryptedAccessToken);
    }
}
