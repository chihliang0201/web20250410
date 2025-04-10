<?php
ob_start(); // 開始輸出緩衝區
session_start();
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: https://abc.sheep0201.xyz');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Origin: https://abc.sheep0201.xyz');
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');
    header('Access-Control-Allow-Headers: Content-Type');
    http_response_code(200);
    exit;
}

const DB_SERVER    = "127.0.0.1";
const DB_USER_NAME = "fixcar";
const DB_PASSWORD  = "8K9vZJfmtszh5ljzVF";
const DB_NAME      = "project";

function create_connection()
{
    $conn = mysqli_connect(DB_SERVER, DB_USER_NAME, DB_PASSWORD, DB_NAME);
    if (!$conn) {
        throw new Exception("資料庫連線失敗: " . mysqli_connect_error());
    }
    mysqli_set_charset($conn, "utf8");
    return $conn;
}

function check_suspension($conn, $u_id)
{
    $stmt = $conn->prepare("SELECT is_suspended FROM users WHERE user_id = ?");
    if (!$stmt) {
        return ["state" => false, "message" => "SQL 準備失敗: " . $conn->error];
    }
    $stmt->bind_param("s", $u_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 0) {
        return ["state" => false, "message" => "無效的用戶"];
    }
    $user = $result->fetch_assoc();
    $stmt->close();
    if ($user['is_suspended'] == 1) {
        return ["state" => false, "message" => "您的帳號已被停權，無法進行操作"];
    }
    return ["state" => true];
}

function respond($state, $message, $data = null)
{
    header('Content-Type: application/json');
    echo json_encode(["state" => $state, "message" => $message, "data" => $data]);
    exit;
}

function handleGetMessages($conn, $data)
{
    error_log("進入 get_messages 處理");
    if (!isset($_COOKIE['level']) || $_COOKIE['level'] != 1) {
        error_log("權限檢查失敗: level=" . ($_COOKIE['level'] ?? '未設置'));
        respond(false, "僅管理員可查看所有訊息");
    }
    $u_id = isset($data['u_id']) ? trim($data['u_id']) : null;
    error_log("u_id: " . $u_id);
    if (!$u_id) {
        error_log("缺少 u_id 參數");
        respond(false, "缺少 u_id 參數");
    }
    error_log("準備 SQL 查詢");
    $stmt = $conn->prepare("
        SELECT cm.id, cm.u_id, cm.sender, cm.message, cm.created_at, cm.is_read, u.real_name 
        FROM chat_messages cm 
        LEFT JOIN users u ON cm.u_id = u.user_id 
        WHERE cm.u_id = ? AND cm.is_resolved = 0
        ORDER BY cm.created_at ASC
    ");
    if (!$stmt) {
        error_log("SQL 準備失敗: " . $conn->error);
        respond(false, "SQL 準備失敗: " . $conn->error);
    }
    $stmt->bind_param("s", $u_id);
    error_log("執行 SQL 查詢");
    if (!$stmt->execute()) {
        error_log("SQL 執行失敗: " . $stmt->error);
        respond(false, "SQL 執行失敗: " . $stmt->error);
    }
    $result = $stmt->get_result();
    $messages = [];
    while ($row = $result->fetch_assoc()) {
        $messages[] = $row;
    }
    error_log("查詢結果: " . print_r($messages, true));
    respond(true, "取得訊息成功", ["messages" => $messages]);
}

try {
    $conn = create_connection();
    $method = $_SERVER['REQUEST_METHOD'];
    $data = json_decode(file_get_contents('php://input'), true);
    $action = $_GET['action'] ?? '';

    // 記錄收到的請求資料（用於除錯）
    error_log("收到請求: " . print_r($data, true));
    error_log("收到的 Cookie: " . print_r($_COOKIE, true));

    switch ($method) {
        case 'POST':
            if ($action === 'user_get_messages') {
                if (isset($data['user_id'])) {
                    $user_id = trim($data['user_id']);
                    if (empty($user_id)) {
                        error_log("user_id 為空");
                        respond(false, "user_id 不能為空");
                    }
                    $suspension_check = check_suspension($conn, $user_id);
                    if (!$suspension_check['state']) {
                        respond(false, $suspension_check['message']);
                    }

                    $stmt = $conn->prepare("
                        SELECT id, u_id, sender, message, created_at, is_read, is_resolved 
                        FROM chat_messages 
                        WHERE u_id = ? AND is_resolved = 0
                        ORDER BY created_at ASC
                    ");
                    if (!$stmt) {
                        error_log("SQL 準備失敗: " . $conn->error);
                        respond(false, "SQL 準備失敗: " . $conn->error);
                    }
                    $stmt->bind_param("s", $user_id);
                    if (!$stmt->execute()) {
                        error_log("SQL 執行失敗: " . $stmt->error);
                        respond(false, "SQL 執行失敗: " . $stmt->error);
                    }
                    $result = $stmt->get_result();
                    $messages = [];
                    while ($row = $result->fetch_assoc()) {
                        $messages[] = $row;
                    }
                    error_log("查詢結果: " . print_r($messages, true));
                    respond(true, "取得訊息成功", ["messages" => $messages]);
                } else {
                    error_log("缺少 user_id 參數");
                    respond(false, "缺少 user_id 參數");
                }
            }

            if ($action === 'send_message') {
                if (!isset($data['user_id']) || !isset($data['message']) || empty(trim($data['message']))) {
                    respond(false, "缺少 u_id 或訊息內容");
                }
                $u_id = trim($data['user_id']);
                $suspension_check = check_suspension($conn, $u_id);
                if (!$suspension_check['state']) {
                    respond(false, $suspension_check['message']);
                }
                $message = trim($data['message']);
                $sender = isset($data['sender']) && $data['sender'] === 'admin' ? 'admin' : 'user';
                $created_at = date('Y-m-d H:i:s');
                $is_read = ($sender === 'admin') ? 1 : 0;

                $stmt = $conn->prepare("INSERT INTO chat_messages (u_id, sender, message, created_at, is_read) VALUES (?, ?, ?, ?, ?)");
                if (!$stmt) {
                    error_log("SQL 準備失敗: " . $conn->error);
                    respond(false, "SQL 準備失敗: " . $conn->error);
                }
                $stmt->bind_param("ssssi", $u_id, $sender, $message, $created_at, $is_read);
                if ($stmt->execute()) {
                    if ($sender === 'admin') {
                        $update_stmt = $conn->prepare("UPDATE chat_messages SET is_read = 1 WHERE u_id = ? AND sender = 'user'");
                        $update_stmt->bind_param("s", $u_id);
                        $update_stmt->execute();
                        $update_stmt->close();
                    }
                    respond(true, "訊息發送成功");
                } else {
                    error_log("訊息發送失敗: " . $stmt->error);
                    respond(false, "訊息發送失敗: " . $stmt->error);
                }
            }

            if ($action === 'get_messages') {
                handleGetMessages($conn, $data);
            }
            break;

        default:
            error_log("未匹配到任何 action: method=$method, action=$action");
            respond(false, "無效的請求方法或 action");
    }
} catch (Exception $e) {
    error_log("錯誤: " . $e->getMessage());
    respond(false, "操作失敗: " . $e->getMessage());
} finally {
    if (isset($stmt)) $stmt->close();
    if (isset($conn)) $conn->close();
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Origin: https://chihliang0201.github.io.');
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Methods: GET, POST, DELETE');
    header('Access-Control-Allow-Headers: Content-Type');
    http_response_code(200);
    exit;
}

ob_end_clean(); // 清理緩衝區
