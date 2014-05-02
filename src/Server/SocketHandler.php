<?php

namespace Lethe\Whois\Server;

class SocketHandler {

    public function execute($query, $args)
    {
        $fs = @call_user_func_array('fsockopen', $args);
        if (!$fs) {
            throw new Exception();
        }
        fwrite($fs, $query . "\r\n");
        $buffer = '';
        while (!feof($fs)) {
            $buffer .= fgets($fs);
        }
        fclose($fs);
        return $buffer;
    }

} 