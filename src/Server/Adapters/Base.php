<?php

namespace Lethe\Whois\Server\Adapters;

use Lethe\Whois\Record;
use Lethe\Whois\Server\SocketHandler;

class Base {

    protected $type;
    protected $allocation;
    protected $host;
    protected $options;
    protected $buffer = [];

    const DEFAULT_WHOIS_PORT = 43;

    public function __construct($type, $allocation, $host, $options)
    {
        $this->type = $type;
        $this->allocation = $allocation;
        $this->host = $host;
        $this->options = $options;
    }

    public function getType()
    {
        return $this->type;
    }

    public function getAllocation()
    {
        return $this->allocation;
    }

    public function getHost()
    {
        return $this->host;
    }

    public function getOptions()
    {
        return $this->options;
    }

    public function lookup($domain)
    {
        $this->request($domain);
        return new Record($this, $this->buffer);
    }

    protected function request($domain)
    {
        $response = $this->querySocket($domain, $this->host);
        $this->appendBuffer($response, $this->host);
    }

    protected function querySocket($query, $host, $port = null)
    {
        $args = [];
        $args[] = $host;
        $args[] = isset($this->options['port']) ? $this->options['port'] : self::DEFAULT_WHOIS_PORT;
        $handler = new SocketHandler();
        return $handler->execute($query, $args);
    }

    protected function appendBuffer($body, $host)
    {
        $this->buffer[] = new Record\Part(['body' => $body, 'host' => $host]);
    }

} 