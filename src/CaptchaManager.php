<?php

namespace Trustcaptcha;

use Exception;

require_once 'model/VerificationToken.php';
require_once 'model/VerificationResult.php';

class CaptchaManager {

    public static function getVerificationResult(string $secretKey, string $base64verificationToken): VerificationResult {
        $verificationToken = self::getVerificationToken($base64verificationToken);

        $url = "{$verificationToken->apiEndpoint}/verifications/{$verificationToken->verificationId}/assessments";
        $headers = [
            "tc-authorization: $secretKey",
            "tc-library-language: php",
            "tc-library-version: 1.0"
        ];

        $options = [
            "http" => [
                "header" => implode("\r\n", $headers),
                "method" => "GET"
            ]
        ];
        $context = stream_context_create($options);
        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            $http_response_code = $http_response_header[0] ?? null;
            if (strpos($http_response_code, "403") !== false) {
                throw new SecretKeyInvalidException("Secret key is invalid");
            } elseif (strpos($http_response_code, "404") !== false) {
                throw new VerificationNotFoundException("Verification not found");
            } elseif (strpos($http_response_code, "423") !== false) {
                throw new VerificationNotFinishedException("Verification not finished");
            }
            throw new Exception("Failed to retrieve verification result");
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
