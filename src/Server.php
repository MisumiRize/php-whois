<?php

namespace Lethe\Whois;

use Lethe\Json\Util;
use Lethe\Whois\Server\Adapters;

class Server {

    private static $definitions = [];

    public static function loadDefinitions()
    {
        $files = glob(realpath(__DIR__ . '/../data') . '/*.json');
        array_walk($files, ['self', 'loadJson']);
    }

    public static function loadJson($file)
    {
        $pathinfo = pathinfo($file);
        $json = json_decode(Util::stripJsonComments(@file_get_contents($file)), true);
        array_walk($json, function($settings, $allocation) use ($pathinfo) {
            $host = isset($settings['host']) ? $settings['host'] : null;
            unset($settings['host']);
            self::define($pathinfo['filename'], $allocation, $host, $settings);
        });
    }

    public static function define($type, $allocation, $host, $options = [])
    {
        if (!isset(self::$definitions[$type])) {
            self::$definitions[$type] = [];
        }
        self::$definitions[$type][] = [$allocation, $host, $options];
    }

    public static function getDefinitions($type = null)
    {
        if ($type === null) {
            return self::$definitions;
        }
        return isset(self::$definitions[$type]) ? self::$definitions[$type] : null;
    }

    public static function resetDefinitions()
    {
        self::$definitions = [];
    }

    public static function factory($type, $allocation, $host, $options = [])
    {
        $adapterClass = isset($options['adapter']) ?
            'Lethe\Whois\Server\Adapters\\' . ucfirst($options['adapter']) :
            'Lethe\Whois\Server\Adapters\Standard';
        unset($options['adapter']);
        if (class_exists($adapterClass)) {
            $adapter = new $adapterClass($type, $allocation, $host, $options);
        } else {
            $adapter = new Adapters\Standard($type, $allocation, $host, $options);
        }
        return $adapter;
    }

    public static function guess($string)
    {
        if (self::matchesTld($string)) {
            return self::factory('tld', '.', 'whois.iana.org');
        }

        if (self::matchesIp($string)) {
            return self::findForIp($string);
        }

        if ($server = self::findForDomain($string)) {
            return $server;
        }
        if (self::matchesAsn($string)) {
            return self::findForAsn($string);
        }
        throw new ServerNotFoundException('Unable to find a WHOIS server for ' . $string);
    }

    private static function matchesTld($string)
    {
        return preg_match('/^\.(xn--)?[a-z0-9]+\z/', $string);
    }

    private static function matchesIp($string)
    {
        return self::hasValidIpv4($string);
    }

    private static function matchesAsn($string)
    {
        return preg_match('/\Aas\d+\z/i', $string);
    }

    private static function findForIp($string)
    {
        $definitions = self::getDefinitions('ipv4');
        foreach ($definitions as $definition) {
            if ((new IpAddr($definition[0]))->includes($string)) {
                return call_user_func_array(['self', 'factory'], array_merge(['ipv4'], $definition));
            }
        };
        throw new AllocationUnknownException('IP Allocation for ' . $string . ' unknown. Server definitions might be outdated.');
    }

    private static function findForDomain($string)
    {
        $definitions = self::getDefinitions('tld');
        foreach ($definitions as $definition) {
            if (preg_match('/' . preg_quote($definition[0]) . '\z/', $string)) {
                return call_user_func_array(['self', 'factory'], array_merge(['tld'], $definition));
            }
        };
        return null;
    }

    private static function findForAsn($string)
    {
        preg_match('/\Aas(\d+)\z/i', $string, $matches);
        $asn = $matches[1];
        $type = $asn <= 65535 ? 'asn16' : 'asn32';
        $definitions = self::getDefinitions($type);
        foreach ($definitions as $definition) {
            $range = explode(' ', $definition[0]);
            if ($asn >= $range[0] && $asn <= end($range)) {
                return call_user_func_array(['self', 'factory'], array_merge([$type], $definition));
            }
        }
        throw new AllocationUnknownException('Unknown AS number - ' . $asn);
    }

    private static function hasValidIpv4($addr)
    {
        if (!preg_match('/\A(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z/', $addr, $matches)) {
            return false;
        }
        array_shift($matches);
        return array_reduce($matches, function($v, $w) {
            return $v && $w < 256;
        }, true);
    }

    private static function hasValidIpv6($addr)
    {

        if (preg_match('/\A[\dA-Fa-f]{1,4}(:[\dA-Fa-f]{1,4})*\Z/', $addr)
            || preg_match('/\A[\dA-Fa-f]{1,4}(:[\dA-Fa-f]{1,4})*::([\dA-Fa-f]{1,4}(:[\dA-Fa-f]{1,4})*)?\Z/', $addr)
            || preg_match('/\A::([\dA-Fa-f]{1,4}(:[\dA-Fa-f]{1,4})*)?\Z/', $addr)) {
            return true;
        }
        if (preg_match('/\A[\dA-Fa-f]{1,4}(:[\dA-Fa-f]{1,4})*:/', $addr, $matches)
            && self::hasValidIpv4($matches[1])) {
            return true;
        }
        if (preg_match('/\A[\dA-Fa-f]{1,4}(:[\dA-Fa-f]{1,4})*::([\dA-Fa-f]{1,4}(:[\dA-Fa-f]{1,4})*:)?/', $addr, $matches)
            && self::hasValidIpv4($matches[1])) {
            return true;
        }
        if (preg_match('/\A::([\dA-Fa-f]{1,4}(:[\dA-Fa-f]{1,4})*:)?/', $addr, $matches)
            && self::hasValidIpv4($matches[1])) {
            return true;
        }
        return false;
    }

}

Server::loadDefinitions();

