<?php

namespace Lethe\Whois;

class IpAddr {

    private $ipAddr;
    private $mask;

    public function __construct($ipAddr)
    {
        list($this->ipAddr, $this->mask) = explode('/', $ipAddr);
    }

    public function includes($ipAddr)
    {
        $net = ip2long($this->ipAddr);
        $mask = ~((1 << (32 - $this->mask)) - 1);
        $ipNet = ip2long($ipAddr) & $mask;
        return $net == $ipNet;
    }

}
