<?php

/*
 * This file was adapted from a file from Composer (to remove an additional dependency).
 * Included below is the full license file
 *
 * Huge respect to the composer guys for creating such an awesome tool!
 *
 * (c) Nils Adermann <naderman@naderman.de>
 *     Jordi Boggiano <j.boggiano@seld.be>
 *
 * Copyright (c) 2011 Nils Adermann, Jordi Boggiano
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

namespace Shone\Scanner;

/**
 * @author Jordi Boggiano <j.boggiano@seld.be>
 */
class Config
{
    public static $defaultConfig = array(
        'ignore-ext'        => array(),
        'ssl-cert-check'    => 1
    );

    private $config;

    public function __construct()
    {
        // load defaults
        $this->config = static::$defaultConfig;

        $jsonConfig = __DIR__ . '/../../../res/config.json';
        if (is_file($jsonConfig) && is_readable($jsonConfig)) {
            $json = json_decode(file_get_contents($jsonConfig), true);
            $this->merge($json);
        }
    }

    /**
     * Merges new config values with the existing ones (overriding)
     *
     * @param array $config
     */
    public function merge(array $config)
    {
        // override defaults with given config
        if (!empty($config) && is_array($config)) {
            foreach ($config as $key => $val) {
                $this->config[$key] = $val;
            }
        }
    }

    /**
     * Returns a setting
     *
     * @param  string            $key
     * @throws \RuntimeException
     * @return mixed
     */
    public function get($key)
    {
        if (!isset($this->config[$key])) {
            return null;
        }

        return $this->process($this->config[$key]);
    }

    public function raw()
    {
        return $this->config;
    }

    /**
     * Checks whether a setting exists
     *
     * @param  string $key
     * @return bool
     */
    public function has($key)
    {
        return array_key_exists($key, $this->config);
    }

    /**
     * Replaces {$refs} inside a config string
     *
     * @param string a config string that can contain {$refs-to-other-config}
     * @return string
     */
    private function process($value)
    {
        $config = $this;

        if (!is_string($value)) {
            return $value;
        }

        return preg_replace_callback('#\{\$(.+)\}#', function ($match) use ($config) {
            return $config->get($match[1]);
        }, $value);
    }
}
