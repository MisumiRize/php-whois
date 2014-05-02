<?php

namespace Lethe\Whois\Server\Adapters;

use Lethe\Whois\Record;
use Lethe\Whois\Server\SocketHandler;

class Base {

    private $type;
    private $allocation;
    private $host;
    private $options;
    private $buffer = [];

    const DEFAULT_WHOIS_PORT = 43;

    public function __construct($type, $allocation, $host, $options)
    {
        $this->type = $type;
        $this->allocation = $allocation;
        $this->host = $host;
        $this->options = $options;
    }

    public function getHost()
    {
        return $this->host;
    }

    public function lookup($domain)
    {
        $response = $this->querySocket($domain, $this->host);
        $this->appendBuffer($response, $this->host);
        return new Record($this, $this->buffer);
    }

    private function querySocket($query, $host, $port = null)
    {
        $args = [];
        $args[] = $host;
        $args[] = isset($this->options['port']) ? $this->options['port'] : self::DEFAULT_WHOIS_PORT;
        $handler = new SocketHandler();
        return $handler->execute($query, $args);
    }

    private function appendBuffer($body, $host)
    {
        $this->buffer[] = new Record\Part(['body' => $body, 'host' => $host]);
    }

} 