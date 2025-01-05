<?php
/*
Plugin Name: Anti-Deface Plugin
Description: Prevents any changes to WordPress files and reverts them to their original state if changes are detected. Also scans and removes unwanted files (payloads and backdoors).
Version: 1.3
Author: Michael Tallada
*/

class AntiDefacePlugin {
    private $hashes_file = 'file_hashes.json';
    private $vulnerability_api_url = 'https://wpvulndb.com/api/v3/';

    public function __construct() {
        add_action('init', array($this, 'check_file_integrity'));
        add_action('init', array($this, 'scan_for_unwanted_files'));
        add_action('init', array($this, 'scan_for_vulnerable_themes_and_plugins'));
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_filter('all_plugins', array($this, 'hide_plugin_from_plugins_page'));
    }

    public function generate_file_hashes() {
        $files = $this->get_all_files(ABSPATH);
        $hashes = array();

        foreach ($files as $file) {
            $hashes[$file] = md5_file($file);
        }

        file_put_contents($this->hashes_file, json_encode($hashes));
    }

    public function check_file_integrity() {
        if (!file_exists($this->hashes_file)) {
            $this->generate_file_hashes();
            return;
        }

        $hashes = json_decode(file_get_contents($this->hashes_file), true);
        $files = $this->get_all_files(ABSPATH);

        foreach ($files as $file) {
            if (!isset($hashes[$file]) || $hashes[$file] !== md5_file($file)) {
                $this->revert_file($file);
            }
        }
    }

    public function scan_for_unwanted_files() {
        $files = $this->get_all_files(ABSPATH);
        $unwanted_patterns = array('/eval\(/', '/base64_decode\(/', '/shell_exec\(/', '/system\(/', '/passthru\(/', '/exec\(/');
        $shell_script_patterns = array('/\.sh$/', '/\.bash$/');

        foreach ($files as $file) {
            if ($this->is_unwanted_file($file, $unwanted_patterns) || $this->is_shell_script($file, $shell_script_patterns)) {
                unlink($file);
            }
        }
    }

    public function scan_for_vulnerable_themes_and_plugins() {
        $themes = wp_get_themes();
        $plugins = get_plugins();

        foreach ($themes as $theme) {
            $this->check_vulnerability('themes', $theme->get('Name'), $theme->get('Version'));
        }

        foreach ($plugins as $plugin_file => $plugin_data) {
            $this->check_vulnerability('plugins', $plugin_data['Name'], $plugin_data['Version']);
        }
    }

    private function check_vulnerability($type, $name, $version) {
        $response = wp_remote_get($this->vulnerability_api_url . $type . '/' . urlencode($name) . '/' . urlencode($version));
        if (is_wp_error($response)) {
            return;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!empty($data) && isset($data['vulnerabilities'])) {
            foreach ($data['vulnerabilities'] as $vulnerability) {
                // Handle the vulnerability (e.g., notify the admin, disable the theme/plugin, etc.)
                $this->handle_vulnerability($type, $name, $vulnerability);
            }
        }
    }

    private function handle_vulnerability($type, $name, $vulnerability) {
        // Example: Disable the vulnerable theme/plugin
        if ($type === 'themes') {
            switch_theme(WP_DEFAULT_THEME);
        } elseif ($type === 'plugins') {
            deactivate_plugins($name);
        }

        // Notify the admin
        wp_mail(get_option('admin_email'), 'Vulnerability Detected', 'A vulnerability has been detected in ' . $name . ': ' . $vulnerability['title']);
    }

    public function add_admin_menu() {
        add_menu_page(
            'Anti-Deface Report',
            'Anti-Deface',
            'manage_options',
            'anti-deface-report',
            array($this, 'display_admin_page'),
            'dashicons-shield-alt'
        );
    }

    public function display_admin_page() {
        $files = $this->get_all_files(ABSPATH);
        $unwanted_patterns = array('/eval\(/', '/base64_decode\(/', '/shell_exec\(/', '/system\(/', '/passthru\(/', '/exec\(/');
        $unwanted_files = array();

        foreach ($files as $file) {
            if ($this->is_unwanted_file($file, $unwanted_patterns)) {
                $unwanted_files[] = $file;
            }
        }

        echo '<div class="wrap">';
        echo '<h1>Anti-Deface Report</h1>';
        if (!empty($unwanted_files)) {
            echo '<h2>Unwanted Files Detected</h2>';
            echo '<ul>';
            foreach ($unwanted_files as $file) {
                echo '<li>' . esc_html($file) . ' <a href="' . esc_url(admin_url('admin-post.php?action=remove_unwanted_file&file=' . urlencode($file))) . '">Remove</a></li>';
            }
            echo '</ul>';
        } else {
            echo '<p>No unwanted files detected.</p>';
        }
        echo '</div>';
    }

    public function hide_plugin_from_plugins_page($plugins) {
        if (isset($plugins[plugin_basename(__FILE__)])) {
            unset($plugins[plugin_basename(__FILE__)]);
        }
        return $plugins;
    }

    public function remove_unwanted_file() {
        if (isset($_GET['file']) && current_user_can('manage_options')) {
            $file = urldecode($_GET['file']);
            if (file_exists($file)) {
                unlink($file);
            }
        }
        wp_redirect(admin_url('admin.php?page=anti-deface-report'));
        exit;
    }

    private function get_all_files($dir) {
        $files = array();
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    private function revert_file($file) {
        $backup_file = $file . '.bak';

        if (file_exists($backup_file)) {
            copy($backup_file, $file);
        } else {
            unlink($file);
        }
    }

    private function is_unwanted_file($file, $patterns) {
        $content = file_get_contents($file);

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }

    private function is_shell_script($file, $patterns) {
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $file)) {
                return true;
            }
        }

        return false;
    }
}

new AntiDefacePlugin();
register_activation_hook(__FILE__, array('AntiDefacePlugin', 'generate_file_hashes'));
new AntiDefacePlugin();
add_action('admin_post_remove_unwanted_file', array('AntiDefacePlugin', 'remove_unwanted_file'));
?>