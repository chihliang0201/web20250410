<?php
session_start();
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');
header('Access-Control-Allow-Headers: Content-Type');

const DB_SERVER    = "sql109.infinityfree.com";
const DB_USER_NAME = "if0_38646769";
const DB_PASSWORD  = "SQoU7C5kdZo";
const DB_NAME      = "if0_38646769_chihliang0201";

function create_connection()
{
    $conn = mysqli_connect(DB_SERVER, DB_USER_NAME, DB_PASSWORD, DB_NAME);
    if (! $conn) {
        http_response_code(500);
        echo json_encode(["state" => false, "message" => "資料庫連線失敗: " . mysqli_connect_error()]);
        exit;
    }
    mysqli_set_charset($conn, "utf8");
    return $conn;
}

function respond($state, $message, $data = null)
{
    echo json_encode(["state" => $state, "message" => $message, "data" => $data]);
    exit;
}

function generate_uid()
{
    return bin2hex(random_bytes(6)); // 生成 12 字元長度的 u_id，確保小於 128 字元
}

try {
    $conn   = create_connection();
    $method = $_SERVER['REQUEST_METHOD'];
    $data   = json_decode(file_get_contents('php://input'), true);
    $action = $_GET['action'] ?? '';

    switch ($method) {
        case 'GET':
            if ($action === 'get_all_users') {
                if (! isset($_COOKIE['level']) || $_COOKIE['level'] != 1) {
                    respond(false, "僅管理員可查看所有用戶");
                }
                $stmt = $conn->prepare("SELECT user_id, user_name, real_name, email, user_tel, level, user_create_at, is_suspended FROM users ORDER BY user_id DESC");
                $stmt->execute();
                $result = $stmt->get_result();
                $users  = [];
                while ($row = $result->fetch_assoc()) {
                    $users[] = $row;
                }
                respond(true, "取得所有會員資料成功", ["members" => $users]);
            } elseif ($action === 'get_user_reservations') {
                if (! isset($_COOKIE['u_id'])) {
                    respond(false, "用戶未登入");
                }
                $u_id = $_COOKIE['u_id'];
                $stmt = $conn->prepare("SELECT appointments_id, user_name, user_tel, car_model, service_type, appointment_date, car_status, appointment_created_at FROM appointments WHERE u_id = ?");
                $stmt->bind_param("s", $u_id);
                $stmt->execute();
                $result       = $stmt->get_result();
                $reservations = [];
                while ($row = $result->fetch_assoc()) {
                    $reservations[] = $row;
                }
                respond(true, "取得用戶預約資料成功", ["reservations" => $reservations]);
            }

            if ($action === 'get_messages') {
                if (! isset($_COOKIE['level']) || $_COOKIE['level'] != 1) {
                    respond(false, "僅管理員可查看所有訊息");
                }
                $u_id          = isset($_GET['u_id']) ? trim($_GET['u_id']) : null;
                $page          = isset($_GET['page']) ? max(1, (int) $_GET['page']) : 1;
                $rows_per_page = isset($_GET['rows_per_page']) ? max(1, (int) $_GET['rows_per_page']) : 10;
                if (! $u_id) {
                    respond(false, "缺少 u_id 參數");
                }

                $offset = ($page - 1) * $rows_per_page;
                $stmt   = $conn->prepare("
                    SELECT cm.id, cm.u_id, cm.sender, cm.message, cm.created_at, cm.is_read, u.real_name
                    FROM chat_messages cm
                    LEFT JOIN users u ON cm.u_id = u.user_id
                    WHERE cm.u_id = ? AND cm.is_resolved = 0
                    ORDER BY cm.created_at ASC
                    LIMIT ? OFFSET ?
                ");
                if (! $stmt) {
                    respond(false, "SQL 準備失敗: " . $conn->error);
                }
                $stmt->bind_param("sii", $u_id, $rows_per_page, $offset);
                $stmt->execute();
                $result   = $stmt->get_result();
                $messages = [];
                while ($row = $result->fetch_assoc()) {
                    $messages[] = $row;
                }
                // 計算總筆數
                $count_stmt = $conn->prepare("
    SELECT COUNT(*) as total
    FROM chat_messages
    WHERE u_id = ? AND is_resolved = 0
");
                $count_stmt->bind_param("s", $u_id);
                $count_stmt->execute();
                $count_result = $count_stmt->get_result();
                $total        = $count_result->fetch_assoc()['total'];

                respond(true, "取得訊息成功", [
                    "messages"      => $messages,
                    "total"         => $total,
                    "page"          => $page,
                    "rows_per_page" => $rows_per_page,
                ]);
            }

            if ($action === 'get_users_with_messages') {
                if (! isset($_COOKIE['level']) || $_COOKIE['level'] != 1) {
                    respond(false, "僅管理員可查看有諮詢記錄的會員");
                }

                $stmt = $conn->prepare("
                    SELECT DISTINCT u.user_id, u.user_name, u.real_name, u.email, u.user_tel, u.level, u.user_create_at, u.is_suspended,
                        (SELECT COUNT(*)
                         FROM chat_messages cm2
                         WHERE cm2.u_id = u.user_id
                         AND cm2.is_read = 0
                         AND cm2.sender = 'user'
                         AND cm2.is_resolved = 0) as unread_count
                    FROM users u
                    INNER JOIN chat_messages cm ON u.user_id = cm.u_id
                    WHERE cm.is_resolved = 0 AND u.level != 1
                    ORDER BY u.user_id DESC
                ");
                if (! $stmt) {
                    respond(false, "SQL 準備失敗: " + $conn->error);
                }
                $stmt->execute();
                $result = $stmt->get_result();
                $users  = [];
                while ($row = $result->fetch_assoc()) {
                    $users[] = $row;
                }
                respond(true, "取得有諮詢記錄的會員資料成功", ["members" => $users]);
            }

            if ($action === 'get_total_unread_count') {
                if (! isset($_COOKIE['level']) || $_COOKIE['level'] != 1) {
                    respond(false, "僅管理員可查看未讀訊息數量");
                }
                $stmt = $conn->prepare("
                    SELECT COUNT(*) as unread_count
                    FROM chat_messages
                    WHERE is_read = 0 AND sender = 'user' AND is_resolved = 0
                ");
                $stmt->execute();
                $result       = $stmt->get_result();
                $row          = $result->fetch_assoc();
                $unread_count = $row['unread_count'];
                respond(true, "取得未讀訊息總數成功", ["unread_count" => $unread_count]);
            }
            break;

        case 'POST':
            if ($action === 'register') {
                $required = ['user_name', 'real_name', 'password', 'user_tel', 'email'];
                foreach ($required as $field) {
                    if (! isset($data[$field]) || empty(trim($data[$field]))) {
                        respond(false, "缺少必要的欄位: $field");
                    }
                }
                $user_name = trim($data['user_name']);
                $real_name = trim($data['real_name']);
                $password  = password_hash(trim($data['password']), PASSWORD_DEFAULT);
                $user_tel  = trim($data['user_tel']);
                $email     = trim($data['email']);
                $u_id      = generate_uid();
                $level     = isset($data['level']) ? (int) $data['level'] : 2;

                // 檢查帳號是否已存在
                $check_stmt = $conn->prepare("SELECT user_id FROM users WHERE user_name = ?");
                $check_stmt->bind_param("s", $user_name);
                $check_stmt->execute();
                $result = $check_stmt->get_result();
                if ($result->num_rows > 0) {
                    respond(false, "此帳號已存在，請使用其他帳號");
                }
                $check_stmt->close();

                // 插入新用戶
                $stmt = $conn->prepare("INSERT INTO users (user_name, real_name, password, user_tel, email, u_id, level) VALUES (?, ?, ?, ?, ?, ?, ?)");
                if (! $stmt) {
                    respond(false, "SQL 準備失敗: " . $conn->error);
                }
                $stmt->bind_param("ssssssi", $user_name, $real_name, $password, $user_tel, $email, $u_id, $level);
                if ($stmt->execute()) {
                    respond(true, "註冊成功", ["u_id" => $u_id]);
                } else {
                    respond(false, "註冊失敗: " . $stmt->error);
                }
            } elseif ($action === 'login') {
                if (! isset($data['user_name']) || ! isset($data['password'])) {
                    respond(false, "缺少帳號或密碼");
                }
                $user_name = trim($data['user_name']);
                $password  = trim($data['password']);
                $stmt      = $conn->prepare("SELECT user_id, u_id, real_name, level, password, is_suspended FROM users WHERE user_name = ?");
                $stmt->bind_param("s", $user_name);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result->num_rows > 0) {
                    $user = $result->fetch_assoc();
                    if ($user['is_suspended'] == 1) {
                        respond(false, "您的帳號已被停權，請聯繫管理員");
                    }
                    if (password_verify($password, $user['password'])) {
                        respond(true, "登入成功", [
                            "u_id"      => $user['u_id'],
                            "real_name" => $user['real_name'],
                            "level"     => $user['level'],
                        ]);
                    } else {
                        respond(false, "密碼錯誤");
                    }
                } else {
                    respond(false, "帳號不存在");
                }
            } elseif ($action === 'checkuid') {
                if (! isset($data['u_id']) || empty(trim($data['u_id']))) {
                    respond(false, "缺少 u_id");
                }
                $u_id = trim($data['u_id']);
                $stmt = $conn->prepare("SELECT user_id, user_name, real_name, level FROM users WHERE u_id = ?");
                $stmt->bind_param("s", $u_id);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result->num_rows === 1) {
                    $user = $result->fetch_assoc();
                    respond(true, "用戶驗證成功", ["user_id" => $user['user_id'], "user_name" => $user['user_name'], "real_name" => $user['real_name'], "level" => $user['level']]);
                } else {
                    respond(false, "無效的 u_id");
                }
            } elseif ($action === 'check_username') {
                if (! isset($data['user_name']) || empty(trim($data['user_name']))) {
                    respond(false, "缺少帳號欄位");
                }
                $user_name = trim($data['user_name']);
                $stmt      = $conn->prepare("SELECT user_id FROM users WHERE user_name = ?");
                $stmt->bind_param("s", $user_name);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result->num_rows > 0) {
                    respond(false, "此帳號已存在");
                } else {
                    respond(true, "帳號可用");
                }
            } elseif ($action === 'update_profile') {
                if (! isset($data['u_id']) || empty(trim($data['u_id']))) {
                    respond(false, "缺少 u_id");
                }
                $u_id = trim($data['u_id']);

                // 檢查用戶是否存在
                $check_stmt = $conn->prepare("SELECT user_id FROM users WHERE u_id = ?");
                $check_stmt->bind_param("s", $u_id);
                $check_stmt->execute();
                $result = $check_stmt->get_result();
                if ($result->num_rows === 0) {
                    $check_stmt->close();
                    respond(false, "無效的 u_id");
                }
                $check_stmt->close();

                // 更新資料
                $real_name = isset($data['real_name']) ? trim($data['real_name']) : null;
                $user_tel  = isset($data['user_tel']) ? trim($data['user_tel']) : null;
                $email     = isset($data['email']) ? trim($data['email']) : null;
                $password  = isset($data['password']) ? password_hash(trim($data['password']), PASSWORD_DEFAULT) : null;

                $sql    = "UPDATE users SET ";
                $params = [];
                $types  = "";

                if ($real_name) {
                    $sql .= "real_name = ?, ";
                    $params[] = $real_name;
                    $types .= "s";
                }
                if ($user_tel) {
                    $sql .= "user_tel = ?, ";
                    $params[] = $user_tel;
                    $types .= "s";
                }
                if ($email) {
                    $sql .= "email = ?, ";
                    $params[] = $email;
                    $types .= "s";
                }
                if ($password) {
                    $sql .= "password = ?, ";
                    $params[] = $password;
                    $types .= "s";
                }

                // 移除最後的逗號和空格
                $sql = rtrim($sql, ", ");
                $sql .= " WHERE u_id = ?";
                $params[] = $u_id;
                $types .= "s";

                $stmt = $conn->prepare($sql);
                if (! $stmt) {
                    respond(false, "SQL 準備失敗: " . $conn->error);
                }

                $stmt->bind_param($types, ...$params);
                if ($stmt->execute()) {
                    if ($stmt->affected_rows > 0) {
                        respond(true, "會員資料更新成功", ["real_name" => $real_name]);
                    } else {
                        respond(false, "資料未變更");
                    }
                } else {
                    respond(false, "更新失敗: " . $stmt->error);
                }
            }

            if ($action === 'resolve_conversation') {
                if (! isset($_COOKIE['level']) || $_COOKIE['level'] != 1) {
                    respond(false, "僅管理員可結束對話");
                }
                if (! isset($data['u_id']) || empty(trim($data['u_id']))) {
                    respond(false, "缺少 u_id 參數");
                }
                $u_id = trim($data['u_id']);

                // 將該會員的所有訊息標記為已完成
                $stmt = $conn->prepare("UPDATE chat_messages SET is_resolved = 1 WHERE u_id = ?");
                if (! $stmt) {
                    respond(false, "SQL 準備失敗: " . $conn->error);
                }
                $stmt->bind_param("s", $u_id);
                if ($stmt->execute()) {
                    respond(true, "對話已標記為完成");
                } else {
                    respond(false, "標記對話失敗: " . $stmt->error);
                }
            }

            if ($action === 'suspend_user') {
                if (! isset($_COOKIE['level']) || $_COOKIE['level'] != 1) {
                    respond(false, "僅管理員可停權用戶");
                }
                if (! isset($data['user_id']) || ! is_numeric($data['user_id'])) {
                    respond(false, "無效的會員 ID");
                }
                $user_id = $data['user_id'];

                $stmt = $conn->prepare("SELECT user_id, level, is_suspended FROM users WHERE user_id = ?");
                $stmt->bind_param("i", $user_id);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result->num_rows == 0) {
                    respond(false, "會員 ID $user_id 不存在");
                }
                $user = $result->fetch_assoc();
                $stmt->close();

                if ($user['level'] == 1) {
                    respond(false, "無法停權管理員帳號");
                }
                if ($user['is_suspended'] == 1) {
                    respond(false, "您的帳號已被停權，請聯繫管理員");
                }

                $stmt = $conn->prepare("UPDATE users SET is_suspended = 1 WHERE user_id = ?");
                $stmt->bind_param("i", $user_id);
                if ($stmt->execute()) {
                    respond(true, "會員已成功停權");
                } else {
                    respond(false, "停權失敗: " . $stmt->error);
                }
            } elseif ($action === 'unsuspend_user') {
                if (! isset($_COOKIE['level']) || $_COOKIE['level'] != 1) {
                    respond(false, "僅管理員可取消停權用戶");
                }
                if (! isset($data['user_id']) || ! is_numeric($data['user_id'])) {
                    respond(false, "無效的會員 ID");
                }
                $user_id = $data['user_id'];

                $stmt = $conn->prepare("SELECT user_id, is_suspended FROM users WHERE user_id = ?");
                $stmt->bind_param("i", $user_id);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result->num_rows == 0) {
                    respond(false, "會員 ID $user_id 不存在");
                }
                $user = $result->fetch_assoc();
                $stmt->close();

                if ($user['is_suspended'] == 0) {
                    respond(false, "此用戶未被停權");
                }

                $stmt = $conn->prepare("UPDATE users SET is_suspended = 0 WHERE user_id = ?");
                $stmt->bind_param("i", $user_id);
                if ($stmt->execute()) {
                    respond(true, "會員已成功取消停權");
                } else {
                    respond(false, "取消停權失敗: " . $stmt->error);
                }
            }
            break;

        case 'DELETE':
            if ($action === 'delete_user') {
                if (! isset($_COOKIE['level']) || $_COOKIE['level'] != 1) {
                    respond(false, "僅管理員可刪除用戶");
                }
                if (! isset($data['user_id']) || ! is_numeric($data['user_id'])) {
                    respond(false, "無效的會員 ID");
                }
                $user_id = $data['user_id'];
                error_log("接收到的 user_id: " . $user_id);

                $stmt = $conn->prepare("SELECT u_id, level FROM users WHERE user_id = ?");
                $stmt->bind_param("i", $user_id);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result->num_rows == 0) {
                    respond(false, "會員 ID $user_id 不存在");
                }
                $user  = $result->fetch_assoc();
                $u_id  = $user['u_id'];
                $level = $user['level'];
                $stmt->close();

                if ($level == 1) {
                    respond(false, "無法刪除管理員帳號");
                }

                $conn->begin_transaction();

                try {
                    $stmt = $conn->prepare("DELETE FROM appointments WHERE u_id = ?");
                    $stmt->bind_param("s", $u_id);
                    $stmt->execute();
                    $appointments_deleted = $stmt->affected_rows;
                    error_log("已刪除 appointments 記錄數: " . $appointments_deleted);
                    $stmt->close();

                    $stmt = $conn->prepare("DELETE FROM users WHERE user_id = ?");
                    $stmt->bind_param("i", $user_id);
                    $stmt->execute();
                    $users_deleted = $stmt->affected_rows;
                    $stmt->close();

                    if ($users_deleted > 0) {
                        $conn->commit();
                        respond(true, "會員及相關預約刪除成功，刪除了 $appointments_deleted 筆預約記錄");
                    } else {
                        $conn->rollback();
                        respond(false, "會員刪除失敗，可能是資料庫錯誤");
                    }
                } catch (Exception $e) {
                    $conn->rollback();
                    error_log("刪除失敗: " . $e->getMessage());
                    respond(false, "刪除失敗: 資料庫錯誤 - " . $e->getMessage());
                }
            }
            break;

        default:
            respond(false, "無效的請求方法");
    }
} catch (Exception $e) {
    error_log("錯誤: " . $e->getMessage());
    respond(false, "操作失敗: " . $e->getMessage());
} finally {
    if (isset($stmt)) {
        $stmt->close();
    }

    if (isset($conn)) {
        $conn->close();
    }
}
