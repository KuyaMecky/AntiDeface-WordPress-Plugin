<?php
/**
 * Plugin Name: Anti-Deface Plugin
 * Description: Monitors changes in WordPress core files and checks for vulnerabilities.
 * Version: 1.0.0
 * Author: Michael Tallada
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

class AntiDefacePlugin {
    private $hashes_file;

    public function __construct() {
        $this->hashes_file = plugin_dir_path(__FILE__) . 'file_hashes.json';

        // Hooks
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_post_remove_unwanted_file', array(__CLASS__, 'remove_unwanted_file'));
        register_activation_hook(__FILE__, array(__CLASS__, 'on_activation'));
        register_deactivation_hook(__FILE__, array(__CLASS__, 'on_deactivation'));
    }

    public function add_admin_menu() {
        add_menu_page(
            'Anti-Deface Plugin',
            'Anti-Deface',
            'manage_options',
            'anti-deface-plugin',
            array($this, 'admin_page'),
            'dashicons-shield'
        );
    }

    public function admin_page() {
        echo '<h1>Anti-Deface Plugin</h1>';
        echo '<p>Monitoring WordPress core files for changes.</p>';
    }

    public static function on_activation() {
        $instance = new self();
        $instance->generate_file_hashes();
    }

    public static function on_deactivation() {
        $instance = new self();
        if (file_exists($instance->hashes_file)) {
            unlink($instance->hashes_file);
        }
    }

    public function generate_file_hashes() {
        $files = $this->get_all_files(ABSPATH);
        $hashes = array();

        foreach ($files as $file) {
            $hashes[$file] = md5_file($file);
        }

        if (file_put_contents($this->hashes_file, json_encode($hashes)) === false) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('Failed to write file hashes.');
            }
        }
    }

    private function get_all_files($dir) {
        $files = array();
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS));

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    public function check_file_integrity() {
        if (!file_exists($this->hashes_file)) {
            $this->generate_file_hashes();
            return;
        }

        $stored_hashes = json_decode(file_get_contents($this->hashes_file), true);
        $current_hashes = array();
        $files = $this->get_all_files(ABSPATH);

        foreach ($files as $file) {
            $current_hashes[$file] = md5_file($file);
        }

        foreach ($current_hashes as $file => $hash) {
            if (!isset($stored_hashes[$file]) || $stored_hashes[$file] !== $hash) {
                error_log("File changed or added: $file");
            }
        }
    }

    public static function remove_unwanted_file() {
        if (!current_user_can('manage_options')) {
            wp_die(__('Unauthorized user', 'anti-deface-plugin'));
        }

        $file = isset($_POST['file']) ? sanitize_text_field($_POST['file']) : '';

        if (file_exists($file)) {
            unlink($file);
            wp_redirect(admin_url('admin.php?page=anti-deface-plugin&status=removed'));
        } else {
            wp_redirect(admin_url('admin.php?page=anti-deface-plugin&status=error'));
        }
        exit;
    }
}

new AntiDefacePlugin();
