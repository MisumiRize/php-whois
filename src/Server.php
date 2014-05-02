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
        return isset($type) ? self::$definitions[$type] : self::$definitions;
    }

    public static function factory($type, $allocation, $host, $options = [])
    {
        $adapterClass = isset($options['adapter']) ? 'Adapters//' . $options['adapter'] : 'Adapters//Base';
        unset($options['adapter']);
        if (class_exists($adapterClass)) {
            $adapter = new $adapterClass($type, $allocation, $host, $options);
        } else {
            $adapter = new Adapters\Base($type, $allocation, $host, $options);
        }
        return $adapter;
    }

    public static function guess($string)
    {
        if (self::matchesTld($string)) {
            return self::factory('tld', '.', 'whois.iana.org');
        }

        if ($server = self::findForDomain($string)) {
            return $server;
        }
    }

    private static function matchesTld($string)
    {
        return preg_match('/^\.(xn--)?[a-z0-9]+\z/', $string);
    }

    private static function findForDomain($string)
    {
        $defiinitions = self::getDefinitions('tld');
        foreach ($defiinitions as $definition) {
            if (preg_match('/' . preg_quote($definition[0]) . '\z/', $string)) {
                return call_user_func_array(['self', 'factory'], array_merge(['tld'], $definition));
            }
        };
        return null;
    }

}

Server::loadDefinitions();

