<?php

namespace Trustcaptcha;

use Exception;

require_once 'model/VerificationToken.php';
require_once 'model/VerificationResult.php';

class CaptchaManager {

    public static function getVerificationResult(string $secretKey, string $base64verificationToken, array $proxyOptions = null): VerificationResult {

        $verificationToken = self::getVerificationToken($base64verificationToken);

        $url = "{$verificationToken->apiEndpoint}/verifications/{$verificationToken->verificationId}/assessments";
        $headers = [
            "tc-authorization: $secretKey",
            "tc-library-language: php",
            "tc-library-version: 1.2.1"
        ];

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

        if ($proxyOptions !== null) {
            if (isset($proxyOptions['proxy'])) {
                $proxy = $proxyOptions['proxy'];
                if (strpos($proxy, 'tcp://') === 0) {
                    $proxy = 'http://' . substr($proxy, strlen('tcp://'));
                }
                curl_setopt($ch, CURLOPT_PROXY, $proxy);
            }
            if (isset($proxyOptions['username'], $proxyOptions['password'])) {
                curl_setopt($ch, CURLOPT_PROXYUSERPWD, "{$proxyOptions['username']}:{$proxyOptions['password']}");
            }
        }

        $response = curl_exec($ch);
        $httpStatusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($response === false) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new Exception("cURL error: " . $error);
        }
        curl_close($ch);

        if ($httpStatusCode === 403) {
            throw new SecretKeyInvalidException("Secret key is invalid");
        } elseif ($httpStatusCode === 404) {
            throw new VerificationNotFoundException("Verification not found");
        } elseif ($httpStatusCode === 423) {
            throw new VerificationNotFinishedException("Verification not finished");
        } elseif ($httpStatusCode < 200 || $httpStatusCode >= 300) {
            throw new Exception("Failed to retrieve verification result: HTTP $httpStatusCode");
        }

        return new VerificationResult($response);
    }

    private static function getVerificationToken(string $verificationToken): VerificationToken {
        $decodedVerificationToken = base64_decode($verificationToken);
        if ($decodedVerificationToken === false) {
            throw new VerificationTokenInvalidException("Invalid base64 encoded token");
        }

        $data = json_decode($decodedVerificationToken);
        if (!isset($data->apiEndpoint, $data->verificationId, $data->encryptedAccessToken)) {
            throw new VerificationTokenInvalidException("Missing required fields in verification token");
        }

        return new VerificationToken($data->apiEndpoint, $data->verificationId, $data->encryptedAccessToken);
    }
}

class SecretKeyInvalidException extends Exception {}
class VerificationTokenInvalidException extends Exception {}
class VerificationNotFoundException extends Exception {}
class VerificationNotFinishedException extends Exception {}
