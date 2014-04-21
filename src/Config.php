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
    /**
     * @var array
     */
    public static $defaultConfig = array(
        'ssl-cert-check'    => 1,
        'ignore-ext'        => array(
            'avi',
            'bmp',
            'doc',
            'docx',
            'gif',
            'ico',
            'jpeg',
            'jpg',
            'json',
            'lock',
            'log',
            'md',
            'mkv',
            'mp3',
            'mpeg',
            'mpg',
            'pdf',
            'png',
            'tar',
            'txt',
            'yml',
            'zip'
        )
    );

    /**
     * @var array
     */
    private $config;

    /**
     * @var string
     */
    private $config_file;

    /**
     * Build a new config object
     *
     * @return Shone\Scanner\Config
     * @codeCoverageIgnore
     */
    public function __construct()
    {
        // load defaults
        $this->config = static::$defaultConfig;

        // Get home directory
        if (isset($_SERVER['HOME'])) {
            $home = $_SERVER['HOME'];
        } elseif (isset($_SERVER['HOMEDRIVE']) && isset($_SERVER['HOMEPATH'])) {
            $home = $_SERVER['HOMEDRIVE'] . '/' . $_SERVER['HOMEPATH'];
        } else {
            $home = getcwd();
        }

        // Attempt to load a custom config
        $this->config_file = $home . '/shone.json';
        if (is_file($this->config_file) && is_readable($this->config_file)) {
            $json = json_decode(file_get_contents($this->config_file), true);
            $this->merge($json);
        }
    }

    /**
     * Returns the path to the config file
     *
     * @return string
     */
    public function getConfigFile()
    {
        return $this->config_file;
    }

    /**
     * Save the config file to the home folder of the user
     *
     * @return boolean
     * @codeCoverageIgnore
     */
    public function save()
    {
        return file_put_contents($this->config_file, json_encode($this->config)) > 0;
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
     * Set a key
     *
     * @param string $key   Key of the config
     * @param string $value Value of the config
     *
     * @return Shone\Scanner\Config
     */
    public function set($key, $value)
    {
        $this->config[$key] = $value;
        return $this;
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
