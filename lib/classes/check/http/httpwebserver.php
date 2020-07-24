<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Verifies http/webserver configuration
 *
 * @package    core
 * @category   check
 * @copyright  2020 Kristian Ringer <kristian.ringer@catalyst-au.net>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace core\check\http;
defined('MOODLE_INTERNAL') || die();

use core\check\check;
use core\check\result;
use curl;
use html_writer;

/**
 * Verifies http/webserver configuration
 *
 * @package    core
 * @copyright  2020 Kristian Ringer <kristian.ringer@catalyst-au.net>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class httpwebserver extends check {

    /**
     * Get the short check name
     *
     * @return string
     */
    public function get_name(): string {
        return get_string('check_httpwebserver_name', 'report_security');
    }

    /**
     * Check if a moodle url begins with https
     *
     * @param $url string the url to check
     * @return bool
     */
    private function is_url_https(string $url): bool {
        return substr($url, 0, 5) === 'https';
    }

    /**
     * Check if the URL is rewritten correctly when visiting different pages.
     *
     * @return bool
     */
    public function is_url_rewriting_correct(): bool {
        global $CFG;
        $error = false;
        $results = [];
        if (!self::is_url_https($CFG->wwwroot)) {
            $httpwwwroot = $CFG->wwwroot;
            $siteishttp = true;
        } else {
            // Our site is https, continue and assert some more tests that http requests redirect to https.
            $httpwwwroot = str_replace('https://', 'http://', $CFG->wwwroot);
            $siteishttp = false;
        }

        $tests = [
            'urlthatdoesnotexist' => [
                'url' => "$CFG->wwwroot/urlthatdoesnotexist",
                'httpcode' => [404],
                'redirect_url' => '',
                'httpsonly' => false,
                'httpcodepass' => true,
                'urlredirectpass' => true,
            ],
            'dashboardnoslash' => [
                'url' => "$CFG->wwwroot/my",
                'httpcode' => [301],
                'redirect_url' => "$CFG->wwwroot/my/",
                'httpsonly' => false,
                'httpcodepass' => true,
                'urlredirectpass' => true,
            ],
            'directorylisting' => [
                'url' => "$CFG->wwwroot/lib/classes/",
                'httpcode' => [404, 403],
                'redirect_url' => '',
                'httpsonly' => false,
                'httpcodepass' => true,
                'urlredirectpass' => true,
            ],
            // The variable redirect_urls_array is an array of the possible valid urls that we can redirect to.
            'httpurlnoredirect' => [
                'url' => "$httpwwwroot/help.php?identifier=defaulthomepageuser&component=moodle",
                'httpcode' => [302],
                'redirect_urls_array' => [
                    "$CFG->wwwroot/help.php?identifier=defaulthomepageuser&component=moodle"
                ],
                'httpsonly' => true,
                'httpcodepass' => true,
                'urlredirectpass' => true,
            ],
            'httpurlthatdoesnotexist' => [
                'url' => "$httpwwwroot/urlthatdoesnotexist",
                'httpcode' => [302],
                'redirect_urls_array' => [
                    "$CFG->wwwroot/urlthatdoesnotexist",
                ],
                'httpsonly' => true,
                'httpcodepass' => true,
                'urlredirectpass' => true,
            ],
            'httpdashboardnoslash' => [
                'url' => "$httpwwwroot/my",
                'httpcode' => [302],
                'redirect_urls_array' => [
                    "$CFG->wwwroot/my/",
                    "$CFG->wwwroot/my"
                ],
                'httpsonly' => true,
                'httpcodepass' => true,
                'urlredirectpass' => true,
            ],
        ];
        $this->tests = $tests;

        foreach ($tests as $test) {
            if ($test['httpsonly'] === true && $siteishttp) {
                continue;
            }
            [$httpcode, $redirecturl] = $this->curl($test['url']);
            $test['actualhttpcode'] = $httpcode;
            $test['actualredirecturl'] = $redirecturl;
            // Get the list of correct http codes from the test array.
            // This also tests for http -> https if $CFG->wwwroot is https.
            if (!in_array($httpcode, $test['httpcode'])) {
                $test['httpcodepass'] = false;
                $error = true;
            }
            if (isset($test['redirect_url']) && $redirecturl !== $test['redirect_url']) {
                $test['urlredirectpass'] = false;
                $error = true;
            }
            $results[] = $test;
        }
        $this->results = $results;
        return !$error;
    }
    /**
     * Get the check detailed info
     * @return string formatted html
     */
    public function get_details(): string {
        if (empty($this->results)) {
            return get_string('check_httpwebserver_details_correct', 'report_security');
        }
        $table = new \html_table();
        $table->data = [];
        $table->head  = [
            get_string('check_httpwebserver_url_tried', 'report_security'),
            get_string('check_httpwebserver_expected_httpcode', 'report_security'),
            get_string('check_httpwebserver_expected_url', 'report_security'),
            get_string('check_httpwebserver_actual_httpcode', 'report_security'),
            get_string('check_httpwebserver_actual_url', 'report_security'),
        ];
        $table->colclasses = [
            'leftalign tried',
            'leftalign status',
            'leftalign check',
            'leftalign summary',
            'leftalign action',
        ];
        $table->id = 'checkhttpwebservertable';
        $table->attributes = ['class' => 'admintable report generaltable'];

        foreach ($this->results as $result) {
            $row = [];
            // Tried url.
            $row[] = html_writer::link($result['url'], $result['url']);
            // Expected http code.
            $row[] = implode(', ', $result['httpcode']);
            // Expected url - Check if this is a https or http error, in which case the incoming data is formatted differently.
            if (isset($result['redirect_url'])) {
                $row[] = html_writer::link($result['redirect_url'], $result['redirect_url']);
            } else if (isset($result['redirect_urls_array'])) {
                $row[] = self::get_urls_as_html($result['redirect_urls_array']);
            } else {
                $row[] = html_writer::link($result['url'], $result['url']);
            }
            // Actual http code.
            $cell = new \html_table_cell($result['actualhttpcode']);
            // Conditionally set the background colour to easily tell which part of the test is failing.
            $cell->attributes['class'] = !$result['httpcodepass'] ? 'table-danger' : '';
            $row[] = $cell;
            // Actual redirected url.
            $cell = new \html_table_cell(html_writer::link($result['actualredirecturl'], $result['actualredirecturl']));
            // Conditionally set the background colour to easily tell which part of the test is failing.
            $cell->attributes['class'] = !$result['urlredirectpass'] ? 'table-danger' : '';
            $row[] = $cell;
            $table->data[] = $row;
        }
        return html_writer::table($table);
    }
    /**
     * Get a string of html from an array of URL's.
     *
     * @param $arrayofurls array the array of URL's
     * @return string the urls output as a string of html
     */
    private function get_urls_as_html(array $arrayofurls): string {
        $urlhtml = '';
        foreach ($arrayofurls as $url) {
            $urlhtml .= html_writer::link($url, $url) . '<br>';
        }
        return $urlhtml;
    }

    /**
     * Curl a url and return the response.
     *
     * @param $url string the url to curl
     * @return array
     */
    public function curl(string $url): array {
        $curl = new curl();
        $curl->setopt(['CURLOPT_FOLLOWLOCATION' => false,
                       'CURLOPT_RETURNTRANSFER' => true,
                       'CURLOPT_CONNECTTIMEOUT' => 5,
                       'CURLOPT_TIMEOUT' => 5,
                       'CURLOPT_SSL_VERIFYPEER' => false,
                       'CURLOPT_SSL_VERIFYHOST' => false,
                      ]);
        $curl->get($url);
        $info = $curl->get_info();
        return [$info['http_code'], $info['redirect_url']];
    }

    /**
     * Return result
     * @return result
     */
    public function get_result(): result {
        if (!self::is_url_rewriting_correct()) {
            $status = result::ERROR;
            $summary = get_string('check_httpwebserver_error', 'report_security');
        } else {
            $status = result::OK;
            $summary = get_string('check_httpwebserver_ok', 'report_security');
        }
        $details = $this->get_details();
        return new result($status, $summary, $details);
    }
}

