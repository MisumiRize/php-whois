<?php

namespace Lethe\Whois;

class Client {

    public function lookup($domain)
    {
        $server = Server::guess($domain);
        return $server->lookup($domain);
    }

} 