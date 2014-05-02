<?php

namespace Lethe\Whois;

class Record {

    private $server;
    private $parts;
    private $content;

    public function __construct(Server\Adapters\Base $adapter, array $parts)
    {
        $this->server = $adapter;
        $this->parts = $parts;
    }

    public function getServer()
    {
        return $this->server;
    }

    public function getParts()
    {
        return $this->parts;
    }

    public function getContent()
    {
        if (isset($this->content)) {
            return $this->content;
        }
        $this->content = implode("\n", array_map(function($part) { return $part->getBody(); }, $this->parts));
        return $this->content;
    }

}