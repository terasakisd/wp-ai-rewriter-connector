<?php
/**
 * Plugin Name: WP AIリライター コネクタ
 * Description: WP AIリライター（社内ツール）との接続用プラグイン。Basic認証環境での認証橋渡し・リライト結果のサイトプレビュー・メタディスクリプション連携を提供します。
 * Version: 1.1.0
 * Author: Mikuru Terasaki
 * License: GPL v2 or later
 */

if (!defined('ABSPATH')) {
    exit;
}

// sheets-to-wp-posts（フル版）が有効な場合は機能が重複するため何もしない
if (defined('GSWPP_VERSION')) {
    return;
}

define('WPAIR_VERSION', '1.1.0');

/* =========================================================
 * 1. Basic認証環境でのアプリケーションパスワード対応
 * ========================================================= */

/**
 * サーバーのBasic認証（アクセス制限）が Authorization ヘッダーを消費するため、
 * クライアントは X-WP-App-Auth ヘッダーでWPの認証情報を送る。
 * ここで PHP_AUTH_* に橋渡しし、WP標準のアプリケーションパスワード認証を通す。
 */
function wpair_bridge_app_auth_header() {
    if (empty($_SERVER['HTTP_X_WP_APP_AUTH'])) {
        return;
    }
    if (!preg_match('/^Basic\s+(.+)$/i', trim($_SERVER['HTTP_X_WP_APP_AUTH']), $m)) {
        return;
    }
    $decoded = base64_decode($m[1], true);
    if ($decoded === false || strpos($decoded, ':') === false) {
        return;
    }
    list($user, $pass) = explode(':', $decoded, 2);
    $_SERVER['PHP_AUTH_USER'] = $user;
    $_SERVER['PHP_AUTH_PW']   = $pass;
}
wpair_bridge_app_auth_header();

/*
 * WPはBasic認証を検知するとアプリケーションパスワード機能を自動無効化するため、
 * 明示的に有効化する（衝突は上記の橋渡しで解決済み）。
 */
add_filter('wp_is_application_passwords_available', '__return_true');
add_filter('wp_is_site_protected_by_basic_auth', '__return_false');

/* =========================================================
 * 1.5 REST APIアクセス制限（XSERVER等）の回避用中継口
 * ========================================================= */

/*
 * サーバー側で /wp-json が403でブロックされる環境向けに、
 * admin-ajax.php 経由でREST APIへ橋渡しする中継口。
 * 認証はWP標準のアプリケーションパスワードをそのまま使う（無認証では一切実行されない）。
 * アプリ側はRESTが403のとき自動でこちらに切り替える。
 */

// admin-ajax はREST APIではないため、アプリケーションパスワード認証が既定では働かない。
// この中継アクションのリクエストに限り有効化する
add_filter('application_password_is_api_request', function ($is_api) {
    if (isset($_REQUEST['action']) && $_REQUEST['action'] === 'wpair_proxy') {
        return true;
    }
    return $is_api;
});

function wpair_handle_proxy() {
    if (!is_user_logged_in()) {
        wp_send_json(array('code' => 'wpair_unauthorized', 'message' => '認証に失敗しました'), 401);
    }

    $route   = isset($_POST['route']) ? wp_unslash($_POST['route']) : '';
    $method  = isset($_POST['_method']) ? strtoupper(sanitize_text_field(wp_unslash($_POST['_method']))) : 'GET';
    $allowed = array('GET', 'POST', 'PUT', 'PATCH', 'DELETE');
    if ($route === '' || strpos($route, '/') !== 0 || !in_array($method, $allowed, true)) {
        wp_send_json(array('code' => 'wpair_bad_request', 'message' => '不正なリクエストです'), 400);
    }

    $request = new WP_REST_Request($method, $route);

    // クエリパラメータ（JSONで受け取る）
    if (!empty($_POST['query'])) {
        $query = json_decode(wp_unslash($_POST['query']), true);
        if (is_array($query)) {
            foreach ($query as $key => $value) {
                $request->set_param($key, $value);
            }
        }
    }

    // JSONボディ
    if (!empty($_POST['body'])) {
        $raw = wp_unslash($_POST['body']);
        $request->set_header('Content-Type', 'application/json');
        $request->set_body($raw);
        $json = json_decode($raw, true);
        if (is_array($json)) {
            foreach ($json as $key => $value) {
                $request->set_param($key, $value);
            }
        }
    }

    // バイナリ（画像アップロード等。base64で受け取る）
    if (!empty($_POST['file_base64'])) {
        $binary = base64_decode($_POST['file_base64'], true);
        if ($binary === false) {
            wp_send_json(array('code' => 'wpair_bad_file', 'message' => 'ファイルの読み取りに失敗しました'), 400);
        }
        $content_type = isset($_POST['content_type']) ? sanitize_text_field(wp_unslash($_POST['content_type'])) : 'application/octet-stream';
        $filename     = isset($_POST['filename']) ? sanitize_file_name(wp_unslash($_POST['filename'])) : 'upload.bin';
        $request->set_header('Content-Type', $content_type);
        $request->set_header('Content-Disposition', 'attachment; filename="' . $filename . '"');
        $request->set_body($binary);
    }

    $response = rest_do_request($request);
    $server   = rest_get_server();
    $data     = $server->response_to_data($response, false);

    // ステータス・ヘッダー（X-WP-TotalPages等）ごと包んで返し、アプリ側で復元する
    wp_send_json(array(
        'status'  => $response->get_status(),
        'headers' => $response->get_headers(),
        'data'    => $data,
    ), 200);
}
add_action('wp_ajax_wpair_proxy', 'wpair_handle_proxy');
add_action('wp_ajax_nopriv_wpair_proxy', 'wpair_handle_proxy');

/* =========================================================
 * 2. リライト結果の一時プレビュー（実テーマ表示・記事本体は無傷）
 * ========================================================= */

class WPAIR_Preview {

    private static $preview_post_id = 0;
    private static $preview_data = null;

    public static function init() {
        add_action('rest_api_init', array(__CLASS__, 'register_routes'));
        add_action('wp', array(__CLASS__, 'maybe_render_preview'));
        add_action('pre_get_posts', array(__CLASS__, 'allow_preview_of_nonpublic'));
    }

    public static function register_routes() {
        register_rest_route('gswpp/v1', '/preview', array(
            'methods'             => 'POST',
            'callback'            => array(__CLASS__, 'create_preview'),
            'permission_callback' => function () {
                return current_user_can('edit_posts');
            },
        ));
    }

    /**
     * 提案内容を post meta に1時間だけ保存し、トークン付きURLを返す
     */
    public static function create_preview($request) {
        $post_id = (int) $request['post_id'];
        $post    = get_post($post_id);
        if (!$post) {
            return new WP_Error('wpair_not_found', '記事が見つかりません', array('status' => 404));
        }

        $token = wp_generate_password(24, false, false);
        update_post_meta($post_id, '_gswpp_preview', array(
            'title'          => (string) $request['title'],
            'content'        => (string) $request['content'],
            'featured_media' => (int) $request['featured_media'],
            'token'          => $token,
            'expires'        => time() + HOUR_IN_SECONDS,
        ));

        // 非公開記事はパーマリンクが使えないため ?p= 形式で組む
        $base = ($post->post_status === 'publish')
            ? get_permalink($post_id)
            : add_query_arg('p', $post_id, home_url('/'));

        return rest_ensure_response(array(
            'url' => add_query_arg('gswpp_preview', $token, $base),
        ));
    }

    /**
     * トークンが一致する場合のみ、非公開記事も表示対象に含める
     */
    public static function allow_preview_of_nonpublic($query) {
        if (is_admin() || !$query->is_main_query()) {
            return;
        }
        if (empty($_GET['gswpp_preview'])) {
            return;
        }
        $post_id = (int) $query->get('p');
        if (!$post_id) {
            $post_id = (int) $query->get('page_id');
        }
        if (!$post_id) {
            return;
        }
        if (!self::validate_token($post_id)) {
            return;
        }
        $query->set('post_status', array('publish', 'future', 'draft', 'pending', 'private'));
    }

    /**
     * トークン一致時、タイトル・本文を提案内容に差し替えて表示
     */
    public static function maybe_render_preview() {
        if (empty($_GET['gswpp_preview']) || !is_singular()) {
            return;
        }
        $post_id = get_queried_object_id();
        if (!self::validate_token($post_id)) {
            return;
        }

        self::$preview_post_id = $post_id;
        self::$preview_data    = get_post_meta($post_id, '_gswpp_preview', true);

        add_filter('the_title', array(__CLASS__, 'filter_preview_title'), 10, 2);
        add_filter('single_post_title', array(__CLASS__, 'filter_preview_title'), 10, 2);
        add_filter('the_content', array(__CLASS__, 'filter_preview_content'), 9);
        add_filter('get_post_metadata', array(__CLASS__, 'filter_preview_thumbnail'), 10, 4);
        add_filter('wp_robots', function ($robots) {
            $robots['noindex']  = true;
            $robots['nofollow'] = true;
            return $robots;
        });
        nocache_headers();
    }

    private static function validate_token($post_id) {
        $meta = get_post_meta($post_id, '_gswpp_preview', true);
        if (!is_array($meta) || empty($meta['token'])) {
            return false;
        }
        if (!hash_equals($meta['token'], (string) wp_unslash($_GET['gswpp_preview']))) {
            return false;
        }
        if (empty($meta['expires']) || (int) $meta['expires'] < time()) {
            return false;
        }
        return true;
    }

    public static function filter_preview_title($title, $post = 0) {
        $id = is_object($post) ? $post->ID : (int) $post;
        if ($id === self::$preview_post_id && self::$preview_data['title'] !== '') {
            return self::$preview_data['title'];
        }
        return $title;
    }

    public static function filter_preview_content($content) {
        if (get_the_ID() === self::$preview_post_id) {
            return self::$preview_data['content'];
        }
        return $content;
    }

    /**
     * プレビュー表示中、指定されたアイキャッチ画像に差し替える
     */
    public static function filter_preview_thumbnail($value, $object_id, $meta_key, $single) {
        if ($meta_key !== '_thumbnail_id') {
            return $value;
        }
        if ((int) $object_id !== self::$preview_post_id) {
            return $value;
        }
        if (empty(self::$preview_data['featured_media'])) {
            return $value;
        }
        $id = (int) self::$preview_data['featured_media'];
        return $single ? $id : array($id);
    }
}
WPAIR_Preview::init();

/* =========================================================
 * 3. メタディスクリプション連携
 * ========================================================= */

/**
 * REST API から更新可能なメタフィールドとして登録
 */
function wpair_register_meta_fields() {
    register_post_meta('post', '_gswpp_meta_description', array(
        'show_in_rest'  => true,
        'single'        => true,
        'type'          => 'string',
        'auth_callback' => function () {
            return current_user_can('edit_posts');
        },
    ));
}
add_action('init', 'wpair_register_meta_fields');

/**
 * SEOプラグイン無しのサイトでは <meta name="description"> として出力
 */
function wpair_output_meta_description() {
    if (!is_singular()) {
        return;
    }
    if (defined('WPSEO_VERSION') || defined('RANK_MATH_VERSION') || defined('AIOSEO_VERSION') || defined('SEOPRESS_VERSION')) {
        return;
    }
    $desc = (string) get_post_meta(get_queried_object_id(), '_gswpp_meta_description', true);
    if ($desc !== '') {
        echo '<meta name="description" content="' . esc_attr($desc) . '">' . "\n";
    }
}
add_action('wp_head', 'wpair_output_meta_description', 5);

/**
 * 保存時に有効なSEOプラグインのフィールドへ自動コピー（Yoast / Rank Math / SEOPress）
 */
function wpair_sync_meta_description_to_seo_plugins($meta_id, $post_id, $meta_key, $meta_value) {
    if ($meta_key !== '_gswpp_meta_description') {
        return;
    }
    $value = (string) $meta_value;
    if ($value === '') {
        return;
    }
    if (defined('WPSEO_VERSION')) {
        update_post_meta($post_id, '_yoast_wpseo_metadesc', $value);
    }
    if (defined('RANK_MATH_VERSION')) {
        update_post_meta($post_id, 'rank_math_description', $value);
    }
    if (defined('SEOPRESS_VERSION')) {
        update_post_meta($post_id, '_seopress_titles_desc', $value);
    }
}
add_action('added_post_meta',   'wpair_sync_meta_description_to_seo_plugins', 10, 4);
add_action('updated_post_meta', 'wpair_sync_meta_description_to_seo_plugins', 10, 4);
