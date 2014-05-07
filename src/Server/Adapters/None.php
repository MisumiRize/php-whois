<?php

namespace Lethe\Whois\Server\Adapters;

class None extends Base {

    protected function request($domain)
    {
        throw new MethodNotImplementedException();
    }

} 