<?php
/**
 * Plugin Name: Anti-Deface Plugin
 * Description: Monitors changes in WordPress core files and checks for vulnerabilities.
 * Version: 1.0.1
 * Author: Michael Tallada
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

class AntiDefacePlugin {
    private $hashes_file;
    private $index_file;
    private $index_file_backup;

    public function __construct() {
        $this->hashes_file = plugin_dir_path(__FILE__) . 'file_hashes.json';
        $this->index_file = ABSPATH . 'index.php';
        $this->index_file_backup = plugin_dir_path(__FILE__) . 'index_backup.php';

        // Hooks
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_post_remove_unwanted_files', array(__CLASS__, 'remove_unwanted_files'));
        add_action('admin_post_deactivate_plugins', array(__CLASS__, 'deactivate_plugins'));
        add_action('admin_post_delete_plugins', array(__CLASS__, 'delete_plugins'));
        register_activation_hook(__FILE__, array(__CLASS__, 'on_activation'));
        register_deactivation_hook(__FILE__, array(__CLASS__, 'on_deactivation'));
        add_action('init', array($this, 'check_index_file_integrity'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_assets'));
    }

    public function enqueue_assets() {
        wp_enqueue_style('anti-deface-plugin-styles', plugin_dir_url(__FILE__) . 'css.css');
        wp_enqueue_script('anti-deface-plugin-scripts', plugin_dir_url(__FILE__) . 'script.js', array('jquery'), null, true);
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
        echo '<div id="spinner" style="display:none;"><div class="spinner"></div></div>';
        echo '<div class="nav-tab-wrapper">';
        echo '<a href="#scan-wp-content" class="nav-tab nav-tab-active">Scan wp-content</a>';
        echo '<a href="#scan-wp-directory" class="nav-tab">Scan WordPress Directory</a>';
        echo '<a href="#scan-themes-plugins" class="nav-tab">Scan Themes & Plugins</a>';
        echo '</div>';
        echo '<div id="scan-wp-content" class="tab-content">';
        $this->scan_wp_content_tab();
        echo '</div>';
        echo '<div id="scan-wp-directory" class="tab-content" style="display:none;">';
        $this->scan_wp_directory_tab();
        echo '</div>';
        echo '<div id="scan-themes-plugins" class="tab-content" style="display:none;">';
        $this->scan_themes_plugins_tab();
        echo '</div>';
        echo '<script>
            document.addEventListener("DOMContentLoaded", function() {
                const tabs = document.querySelectorAll(".nav-tab");
                const contents = document.querySelectorAll(".tab-content");
                const spinner = document.getElementById("spinner");

                tabs.forEach(tab => {
                    tab.addEventListener("click", function(event) {
                        event.preventDefault();
                        const target = this.getAttribute("href");

                        tabs.forEach(t => t.classList.remove("nav-tab-active"));
                        this.classList.add("nav-tab-active");

                        contents.forEach(content => content.style.display = "none");
                        document.querySelector(target).style.display = "block";
                    });
                });

                document.querySelectorAll("form").forEach(form => {
                    form.addEventListener("submit", function() {
                        spinner.style.display = "block";
                    });
                });
            });
        </script>';
    }

    private function scan_wp_content_tab() {
        if (isset($_POST['scan_wp_content']) && check_admin_referer('scan_wp_content_action', 'scan_wp_content_nonce')) {
            $vulnerabilities = $this->scan_wp_content();
            $this->display_vulnerabilities($vulnerabilities, 'wp-content');
        }

        echo '<form method="post">';
        wp_nonce_field('scan_wp_content_action', 'scan_wp_content_nonce');
        echo '<input type="submit" name="scan_wp_content" value="Scan wp-content for Vulnerabilities" class="button button-primary">';
        echo '</form>';
    }

    private function scan_wp_directory_tab() {
        if (isset($_POST['scan_wp_directory']) && check_admin_referer('scan_wp_directory_action', 'scan_wp_directory_nonce')) {
            $recent_files = $this->scan_wp_directory();
            $this->display_recent_files($recent_files);
        }

        echo '<form method="post">';
        wp_nonce_field('scan_wp_directory_action', 'scan_wp_directory_nonce');
        echo '<input type="submit" name="scan_wp_directory" value="Scan WordPress Directory for Recent and Unwanted Files" class="button button-primary">';
        echo '</form>';
    }

    private function scan_themes_plugins_tab() {
        if (isset($_POST['scan_themes_plugins']) && check_admin_referer('scan_themes_plugins_action', 'scan_themes_plugins_nonce')) {
            $vulnerabilities = $this->scan_themes_plugins();
            $this->display_vulnerabilities($vulnerabilities, 'themes and plugins');
        }

        echo '<form method="post">';
        wp_nonce_field('scan_themes_plugins_action', 'scan_themes_plugins_nonce');
        echo '<input type="submit" name="scan_themes_plugins" value="Scan Themes & Plugins for Vulnerabilities" class="button button-primary">';
        echo '</form>';
    }

    private function display_vulnerabilities($vulnerabilities, $context) {
        if (!empty($vulnerabilities)) {
            echo '<h2>Vulnerabilities Found:</h2>';
            echo '<table class="wp-list-table widefat fixed striped">';
            echo '<thead><tr><th>File</th><th>Issue</th><th>Solution</th><th>Severity</th><th>Date</th><th>Actions</th></tr></thead>';
            echo '<tbody>';
            foreach ($vulnerabilities as $vulnerability) {
                $severity_color = $this->get_severity_color($vulnerability['severity']);
                echo '<tr>';
                echo '<td>' . esc_html($vulnerability['file']) . '</td>';
                echo '<td>' . esc_html($vulnerability['issue']) . '</td>';
                echo '<td>' . esc_html($vulnerability['solution']) . '</td>';
                echo '<td style="color:' . esc_attr($severity_color) . ';">' . esc_html($vulnerability['severity']) . '</td>';
                echo '<td>' . esc_html($vulnerability['date']) . '</td>';
                echo '<td>
                        <button class="button button-primary" onclick="editFile(\'' . esc_js($vulnerability['file']) . '\')">Edit</button>
                        <button class="button button-secondary" onclick="deleteFile(\'' . esc_js($vulnerability['file']) . '\')">Delete</button>
                        <button class="button button-danger" onclick="removeSafely(\'' . esc_js($vulnerability['file']) . '\')">Remove Safely</button>
                      </td>';
                echo '</tr>';
            }
            echo '</tbody>';
            echo '</table>';
        } else {
            echo "<p>No vulnerabilities found in $context.</p>";
        }
    }
    
    private function display_recent_files($recent_files) {
        if (!empty($recent_files)) {
            echo '<h2>Recent and Unwanted Files Found:</h2>';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            echo '<input type="hidden" name="action" value="remove_unwanted_files">';
            wp_nonce_field('remove_unwanted_files_action', 'remove_unwanted_files_nonce');
            echo '<table class="wp-list-table widefat fixed striped">';
            echo '<thead><tr><th><input type="checkbox" id="select-all"></th><th>File</th><th>Date</th><th>Actions</th></tr></thead>';
            echo '<tbody>';
            foreach ($recent_files as $file) {
                echo '<tr>';
                echo '<td><input type="checkbox" name="files[]" value="' . esc_attr($file) . '"></td>';
                echo '<td>' . esc_html($file) . '</td>';
                echo '<td>' . esc_html(date('Y-m-d H:i:s', filemtime($file))) . '</td>';
                echo '<td>
                        <button class="button button-primary" onclick="editFile(\'' . esc_js($file) . '\')">Edit</button>
                        <button class="button button-secondary" onclick="deleteFile(\'' . esc_js($file) . '\')">Delete</button>
                        <button class="button button-danger" onclick="removeSafely(\'' . esc_js($file) . '\')">Remove Safely</button>
                      </td>';
                echo '</tr>';
            }
            echo '</tbody>';
            echo '</table>';
            echo '<input type="submit" value="Remove Selected Files" class="button button-primary">';
            echo '</form>';
        } else {
            echo '<p>No recent or unwanted files found.</p>';
        }
    }
    

    // private function display_recent_files($recent_files) {
    //     if (!empty($recent_files)) {
    //         echo '<h2>Recent and Unwanted Files Found:</h2>';
    //         echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
    //         echo '<input type="hidden" name="action" value="remove_unwanted_files">';
    //         wp_nonce_field('remove_unwanted_files_action', 'remove_unwanted_files_nonce');
    //         echo '<table class="wp-list-table widefat fixed striped">';
    //         echo '<thead><tr><th><input type="checkbox" id="select-all"></th><th>File</th><th>Date</th><th>Actions</th></tr></thead>';
    //         echo '<tbody>';
    //         foreach ($recent_files as $file) {
    //             echo '<tr>';
    //             echo '<td><input type="checkbox" name="files[]" value="' . esc_attr($file) . '"></td>';
    //             echo '<td>' . esc_html($file) . '</td>';
    //             echo '<td>' . esc_html(date('Y-m-d H:i:s', filemtime($file))) . '</td>';
    //             echo '<td><button class="button button-primary" onclick="handleAction(\'' . esc_js($file) . '\')">Take Action</button></td>';
    //             echo '</tr>';
    //         }
    //         echo '</tbody>';
    //         echo '</table>';
    //         echo '<input type="submit" value="Remove Selected Files" class="button button-primary">';
    //         echo '</form>';
    //     } else {
    //         echo '<p>No recent or unwanted files found.</p>';
    //     }
    // }

    private function get_severity_color($severity) {
        $colors = [
            'high' => '#ff0000', // Red
            'medium' => '#ffcc00', // Yellow
            'low' => '#00ff00', // Green
            'default' => '#000000' // Black
        ];
        return $colors[$severity] ?? $colors['default'];
    }

    public static function on_activation() {
        $instance = new self();
        $instance->generate_file_hashes();
        $instance->backup_index_file();
    }

    public static function on_deactivation() {
        $instance = new self();
        if (file_exists($instance->hashes_file)) {
            unlink($instance->hashes_file);
        }
        if (file_exists($instance->index_file_backup)) {
            unlink($instance->index_file_backup);
        }
    }

    public function generate_file_hashes() {
        $files = $this->get_all_files(ABSPATH);
        $hashes = array_map('md5_file', $files);

        if (file_put_contents($this->hashes_file, json_encode($hashes)) === false) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('Failed to write file hashes.');
            }
        }
    }

    private function get_all_files($dir) {
        $files = [];
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
        $current_hashes = array_map('md5_file', $this->get_all_files(ABSPATH));

        foreach ($current_hashes as $file => $hash) {
            if (!isset($stored_hashes[$file]) || $stored_hashes[$file] !== $hash) {
                error_log("File changed or added: $file");
            }
        }
    }

    public function backup_index_file() {
        if (file_exists($this->index_file)) {
            copy($this->index_file, $this->index_file_backup);
        }
    }

    public function check_index_file_integrity() {
        $default_index_content = <<<'EOD'
    <?php
    /**
     * Front to the WordPress application. This file doesn't do anything, but loads
     * wp-blog-header.php which does and tells WordPress to load the theme.
     *
     * @package WordPress
     */
    
    /**
     * Tells WordPress to load the WordPress theme and output it.
     *
     * @var bool
     */
    define( 'WP_USE_THEMES', true );
    
    /** Loads the WordPress Environment and Template */
    require __DIR__ . '/wp-blog-header.php';
    EOD;
    
        if (file_exists($this->index_file)) {
            $current_hash = md5_file($this->index_file);
            $backup_hash = md5_file($this->index_file_backup);
    
            if ($current_hash !== $backup_hash) {
                // Restore from backup
                copy($this->index_file_backup, $this->index_file);
                error_log('index.php file was modified and has been restored from backup.');
            }
        } else {
            // Restore to default content if index.php is missing
            file_put_contents($this->index_file, $default_index_content);
            error_log('index.php file was missing and has been restored to default content.');
        }
    }
    

    public static function remove_unwanted_files() {
        if (!current_user_can('manage_options')) {
            wp_die(__('Unauthorized user', 'anti-deface-plugin'));
        }

        check_admin_referer('remove_unwanted_files_action', 'remove_unwanted_files_nonce');

        $files = isset($_POST['files']) ? array_map('sanitize_text_field', $_POST['files']) : [];

        foreach ($files as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }

        wp_redirect(admin_url('admin.php?page=anti-deface-plugin&status=removed'));
        exit;
    }

    public static function deactivate_plugins() {
        if (!current_user_can('manage_options')) {
            wp_die(__('Unauthorized user', 'anti-deface-plugin'));
        }

        check_admin_referer('deactivate_plugins_action', 'deactivate_plugins_nonce');

        $plugin_files = isset($_POST['files']) ? array_map('sanitize_text_field', $_POST['files']) : [];

        foreach ($plugin_files as $plugin_file) {
            if (is_plugin_active($plugin_file)) {
                deactivate_plugins($plugin_file);
            }
        }

        wp_redirect(admin_url('admin.php?page=anti-deface-plugin&status=deactivated'));
        exit;
    }

    public static function delete_plugins() {
        if (!current_user_can('manage_options')) {
            wp_die(__('Unauthorized user', 'anti-deface-plugin'));
        }

        check_admin_referer('delete_plugins_action', 'delete_plugins_nonce');

        $plugin_files = isset($_POST['files']) ? array_map('sanitize_text_field', $_POST['files']) : [];

        foreach ($plugin_files as $plugin_file) {
            if (file_exists(WP_PLUGIN_DIR . '/' . $plugin_file)) {
                delete_plugins([$plugin_file]);
            }
        }

        wp_redirect(admin_url('admin.php?page=anti-deface-plugin&status=deleted'));
        exit;
    }

    public function scan_wp_content() {
        return $this->scan_directory(WP_CONTENT_DIR, 'wp-content');
    }

    public function scan_wp_directory() {
        $time_limit = strtotime('-1 week'); // Example: files modified in the last week
        return array_filter($this->get_all_files(ABSPATH), function($file) use ($time_limit) {
            return filemtime($file) > $time_limit;
        });
    }

    public function scan_themes_plugins() {
        $vulnerabilities = [];
        $themes = wp_get_themes();
        $plugins = get_plugins();

        foreach ($themes as $theme) {
            $vulnerabilities = array_merge($vulnerabilities, $this->scan_directory($theme->get_stylesheet_directory(), 'theme'));
        }

        foreach ($plugins as $plugin_file => $plugin_data) {
            $vulnerabilities = array_merge($vulnerabilities, $this->scan_directory(WP_PLUGIN_DIR . '/' . dirname($plugin_file), 'plugin'));
        }

        return $vulnerabilities;
    }

    private function scan_directory($dir, $context) {
        $vulnerabilities = [];
        $files = $this->get_all_files($dir);

        foreach ($files as $file) {
            if (strpos(file_get_contents($file), 'eval(') !== false) {
                $vulnerabilities[] = [
                    'file' => $file,
                    'issue' => "Usage of eval() detected in $context",
                    'solution' => 'Remove or replace eval() with safer code',
                    'severity' => 'high',
                    'date' => date('Y-m-d H:i:s', filemtime($file))
                ];
            }
        }

        return $vulnerabilities;
    }
}

new AntiDefacePlugin();
