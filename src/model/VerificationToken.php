<?php

class VerificationToken {
    public $apiEndpoint;
    public $verificationId;
    public $encryptedAccessToken;

    public function __construct(string $apiEndpoint, string $verificationId, string $encryptedAccessToken) {
        $this->apiEndpoint = $apiEndpoint;
        $this->verificationId = $verificationId;
        $this->encryptedAccessToken = $encryptedAccessToken;
    }
}
