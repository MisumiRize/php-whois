<?php

namespace Lethe\Whois;

use Lethe\Whois\Record\Parser\WhoisJprsJp;

class ServerTest extends \PHPUnit_Framework_TestCase {

    protected function tearDown()
    {
        Server::resetDefinitions();
        Server::loadDefinitions();
    }

    public function testLoadJson_loadsADefinitionFromJsonFile()
    {
        Server::resetDefinitions();
        Server::loadJson(__DIR__ . '/fixtures/data/tld.json');
        $this->assertEquals(Server::getDefinitions('tld'), [
            ['.ae.org', 'whois.centralnic.com', []],
            ['.ar.com', 'whois.centralnic.com', []],
        ]);
    }

    public function testGetDefinitions_returnsTheDefinitionsHash_WhenTypeArgumentIsNull()
    {
        $d = Server::getDefinitions();
        $this->assertTrue(is_array($d));
        $this->assertEquals(array_keys($d), ['asn16', 'asn32', 'ipv4', 'tld']);
        $d = Server::getDefinitions(null);
        $this->assertTrue(is_array($d));
        $this->assertEquals(array_keys($d), ['asn16', 'asn32', 'ipv4', 'tld']);
    }

    public function testGetDefinitions_returnsTheDefinitionArrayForGivenType_whenTypeArgumentIsNotNullAndGivenTypeExists()
    {
        Server::resetDefinitions();
        Server::define('foo', '.foo', 'whois.foo');
        $d = Server::getDefinitions('foo');
        $this->assertTrue(is_array($d));
        $this->assertEquals($d, [['.foo', 'whois.foo', []]]);
    }

    public function testGetDefinitions_returnsNull_whenTypeArgumentIsNotNullAndGivenTypeDoesntExist()
    {
        $d = Server::getDefinitions('foo');
        $this->assertNull($d);
    }

    public function testDefine_addsANewDefinitionWithGivenArguments()
    {
        Server::define('foo', '.foo', 'whois.foo');
        $this->assertEquals(Server::getDefinitions('foo'), [['.foo', 'whois.foo', []]]);
    }

    public function testDefine_acceptsAHashOfOptions()
    {
        Server::define('foo', '.foo', 'whois.foo', ['foo' => 'bar']);
        $this->assertEquals(Server::getDefinitions('foo'), [['.foo', 'whois.foo', ['foo' => 'bar']]]);
    }

    public function testDefine_acceptsAnyKindOfDefinitionType()
    {
        Server::resetDefinitions();
        Server::define('ipv4', '.foo', 'whois.foo', ['foo' => 'bar']);
        $this->assertEquals(Server::getDefinitions('ipv4'), [['.foo', 'whois.foo', ['foo' => 'bar']]]);
    }

    public function testFactory_returnsAnAdapterInitializedWithGivenArguments()
    {
        $s = Server::factory('tld', '.test', 'whois.test');
        $this->assertEquals($s->getType(), 'tld');
        $this->assertEquals($s->getAllocation(), '.test');
        $this->assertEquals($s->getHost(), 'whois.test');
        $this->assertEquals($s->getOptions(), []);
    }

    public function testFactory_returnsStandardAdapterByDefault()
    {
        $s = Server::factory('tld', '.test', 'whois.test');
        $this->assertInstanceOf('Lethe\Whois\Server\Adapters\Standard', $s);
    }

    public function testFactory_acceptsAnAdapterOptionAndReturnsAnInstanceOfGivenAdapter()
    {
        $s = Server::factory('tld', '.test', 'whois.test', ['adapter' => 'none']);
        $this->assertInstanceOf('Lethe\Whois\Server\Adapters\None', $s);
    }

    public function testFactory_deletesTheAdapterOption()
    {
        $s = Server::factory('tld', '.test', 'whois.test', ['adapter' => 'none', 'foo' => 'bar']);
        $this->assertEquals($s->getOptions(), ['foo' => 'bar']);
    }

    public function testGuess_recognizesTld()
    {
        $s = Server::guess('.com');
        $this->assertInstanceOf('Lethe\Whois\Server\Adapters\Base', $s);
        $this->assertEquals($s->getType(), 'tld');
    }

    public function testGuess_recognizesIpv4()
    {
        $s = Server::guess('127.0.0.1');
        $this->assertInstanceOf('Lethe\Whois\Server\Adapters\Base', $s);
        $this->assertEquals($s->getType(), 'ipv4');
    }

    public function testGuess_recognizesAsn16()
    {
        $s = Server::guess('AS23456');
        $this->assertInstanceOf('Lethe\Whois\Server\Adapters\Base', $s);
        $this->assertEquals($s->getType(), 'asn16');
    }

    public function testGuess_recognizesAsn32()
    {
        $s = Server::guess('AS131072');
        $this->assertInstanceOf('Lethe\Whois\Server\Adapters\Base', $s);
        $this->assertEquals($s->getType(), 'asn32');
    }

    /**
     * @expectedException Lethe\Whois\ServerNotFoundException
     */
    public function testGuess_raises_whenUnrecognizedValue()
    {
        Server::guess('invalid');
    }

    public function testGuess_returnsAIanaAdapter_whenTheInputIsTld()
    {
        $this->assertEquals(Server::guess('.com'), Server::factory('tld', '.', 'whois.iana.org'));
    }

    public function testGuess_returnsAIanaAdapter_whenTheInputIsIdn()
    {
        $this->assertEquals(Server::guess('.xn--fiqs8s'), Server::factory('tld', '.', 'whois.iana.org'));
    }

    public function testGuess_lookupsDefinitionsAndReturnsTheAdapter_whenTheInputIsADomain()
    {
        Server::resetDefinitions();
        Server::define('tld', '.test', 'whois.test');
        $this->assertEquals(Server::guess('example.test'), Server::factory('tld', '.test', 'whois.test'));
    }

    public function testGuess_doesntConsiderTheDotAsARegexpPattern_whenTheInputIsADomain()
    {
        Server::resetDefinitions();
        Server::define('tld', '.no.com', 'whois.no.com');
        Server::define('tld', '.com', 'whois.com');
        $this->assertEquals(Server::guess('antoniocangiano.com'), Server::factory('tld', '.com', 'whois.com'));
    }

}