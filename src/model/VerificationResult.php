<?php

namespace Trustcaptcha;

class VerificationResult {
    public $captchaId;
    public $verificationId;
    public $score;
    public $reason;
    public $origin;
    public $ipAddress;
    public $deviceFamily;
    public $operatingSystem;
    public $browser;
    public $creationTimestamp;
    public $releaseTimestamp;
    public $retrievalTimestamp;
    public $verificationPassed;

    public function __construct($jsonData) {

        $data = is_array($jsonData) ? $jsonData : json_decode($jsonData, true);

        $this->captchaId = $data['captchaId'] ?? '';
        $this->verificationId = $data['verificationId'] ?? '';
        $this->score = $data['score'] ?? 0.0;
        $this->reason = $data['reason'] ?? '';
        $this->origin = $data['origin'] ?? '';
        $this->ipAddress = $data['ipAddress'] ?? '';
        $this->deviceFamily = $data['deviceFamily'] ?? '';
        $this->operatingSystem = $data['operatingSystem'] ?? '';
        $this->browser = $data['browser'] ?? '';
        $this->creationTimestamp = $data['creationTimestamp'] ?? '';
        $this->releaseTimestamp = $data['releaseTimestamp'] ?? '';
        $this->retrievalTimestamp = $data['retrievalTimestamp'] ?? '';
        $this->verificationPassed = $data['verificationPassed'] ?? false;
    }
}
