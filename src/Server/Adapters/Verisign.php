<?php

namespace Lethe\Whois\Server\Adapters;

class Verisign extends Base {

    protected function request($domain)
    {
        $response = $this->querySocket('=' . $domain, $this->host);
        $this->appendBuffer($response, $this->host);
        if ($referral = $this->extractReferral($response)) {
            $response = $this->querySocket($domain, $referral);
            $this->appendBuffer($response, $referral);
        }
    }

    protected function extractReferral($response)
    {
        if (!preg_match('/Domain Name:/', $response)) {
            return null;
        }
        preg_match('/Whois Server: (.+)/', $response, $matches);
        if (count($matches) < 2) {
            return null;
        }
        $server = end($matches);
        $server = trim($server);
        if ($server == 'not defined') {
            return null;
        }
        return $server;
    }

} 