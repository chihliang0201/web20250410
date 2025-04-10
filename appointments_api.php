<?php
session_start();
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');
header('Access-Control-Allow-Headers: Content-Type');

const DB_SERVER    = "sql108.infinityfree.com";
const DB_USER_NAME = "if0_38714653";
const DB_PASSWORD  = "Bc0nlReBsIXMlZJ";
const DB_NAME      = "if0_38714653_web";

function check_suspension($conn, $u_id)
{
    $stmt = $conn->prepare("SELECT is_suspended FROM users WHERE u_id = ?");
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

function create_connection()
{
    $conn = mysqli_connect(DB_SERVER, DB_USER_NAME, DB_PASSWORD, DB_NAME);
    if (!$conn) {
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

try {
    $conn = create_connection();
    $method = $_SERVER['REQUEST_METHOD'];
    $data = json_decode(file_get_contents('php://input'), true);
    $action = $_GET['action'] ?? '';

    switch ($method) {
        case 'GET':
            if ($action === 'get_all_reservations') {
                if (!isset($_COOKIE['level']) || $_COOKIE['level'] != 1) {
                    respond(false, "僅管理員可查看所有預約");
                }
                $stmt = $conn->prepare("SELECT appointments_id, u_id, user_name, user_tel, car_model, service_type, appointment_date, car_status, appointment_created_at, estimated_price, actual_price FROM appointments ORDER BY appointments_id DESC");
                if (!$stmt) {
                    respond(false, "SQL 準備失敗: " . $conn->error);
                }
                $stmt->execute();
                $result = $stmt->get_result();
                $reservations = [];
                while ($row = $result->fetch_assoc()) {
                    $reservations[] = $row;
                }
                respond(true, "取得所有預約資料成功", ["reservations" => $reservations]);
            } elseif ($action === 'get_completed_reservations') {
                if (!isset($_COOKIE['level']) || $_COOKIE['level'] != 1) {
                    respond(false, "僅管理員可查看已完成預約");
                }
                $stmt = $conn->prepare("SELECT appointments_id, u_id, user_name, user_tel, car_model, service_type, appointment_date, car_status, appointment_created_at, estimated_price, actual_price FROM appointments WHERE car_status = '已完成'");
                if (!$stmt) {
                    respond(false, "SQL 準備失敗: " . $conn->error);
                }
                $stmt->execute();
                $result = $stmt->get_result();
                $reservations = [];
                while ($row = $result->fetch_assoc()) {
                    $reservations[] = $row;
                }
                respond(true, "取得已完成預約資料成功", ["reservations" => $reservations]);
            } elseif ($action === 'get_user_reservations') {
                if (!isset($_COOKIE['u_id']) || empty(trim($_COOKIE['u_id']))) {
                    respond(false, "用戶未登入或 u_id 無效");
                }
                $u_id = trim($_COOKIE['u_id']);
                $suspension_check = check_suspension($conn, $u_id);
                if (!$suspension_check['state']) {
                    respond(false, $suspension_check['message']);
                }

                $stmt = $conn->prepare("SELECT appointments_id, user_name, user_tel, car_model, service_type, appointment_date, car_status, appointment_created_at, estimated_price, actual_price FROM appointments WHERE u_id = ? ORDER BY appointment_date ASC");
                if (!$stmt) {
                    respond(false, "SQL 準備失敗: " . $conn->error);
                }
                $stmt->bind_param("s", $u_id);
                if (!$stmt->execute()) {
                    respond(false, "SQL 執行失敗: " . $stmt->error);
                }
                $result = $stmt->get_result();
                $reservations = [];
                while ($row = $result->fetch_assoc()) {
                    $reservations[] = $row;
                }
                respond(true, "取得用戶預約資料成功", ["reservations" => $reservations]);
            }
            break;

        case 'POST':
            if ($action === 'create_reservation') {
                if (!isset($_COOKIE['u_id'])) {
                    respond(false, "用戶未登入");
                }
                $u_id = $_COOKIE['u_id'];
                $suspension_check = check_suspension($conn, $u_id);
                if (!$suspension_check['state']) {
                    respond(false, $suspension_check['message']);
                }

                $required = ['user_name', 'user_tel', 'car_model', 'service_type', 'appointment_date'];
                foreach ($required as $field) {
                    if (!isset($data[$field]) || empty(trim($data[$field]))) {
                        respond(false, "缺少或無效的欄位: $field");
                    }
                }
                $user_name = trim($data['user_name']);
                $user_tel = trim($data['user_tel']);
                $car_model = trim($data['car_model']);
                $service_type = trim($data['service_type']);
                $appointment_date = trim($data['appointment_date']);
                $car_status = '待維修';
                $appointment_created_at = date('Y-m-d H:i:s');
                $estimated_price = isset($data['estimated_price']) && is_numeric($data['estimated_price']) ? floatval($data['estimated_price']) : null;

                if (strtotime($appointment_date) < time()) {
                    respond(false, "預約日期必須為未來時間");
                }

                $stmt = $conn->prepare("INSERT INTO appointments (u_id, user_name, user_tel, car_model, service_type, appointment_date, car_status, appointment_created_at, estimated_price) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
                if (!$stmt) {
                    respond(false, "SQL 準備失敗: " . $conn->error);
                }
                $stmt->bind_param("ssssssssd", $u_id, $user_name, $user_tel, $car_model, $service_type, $appointment_date, $car_status, $appointment_created_at, $estimated_price);
                if ($stmt->execute()) {
                    respond(true, "預約成功", ["appointments_id" => $conn->insert_id]);
                } else {
                    respond(false, "預約失敗: " . $stmt->error);
                }
            } elseif ($action === 'update_reservation') {
                if (!isset($_COOKIE['u_id']) || !isset($_COOKIE['level'])) {
                    respond(false, "用戶未登入");
                }
                $u_id = $_COOKIE['u_id'];
                $suspension_check = check_suspension($conn, $u_id);
                if (!$suspension_check['state']) {
                    respond(false, $suspension_check['message']);
                }
                $level = $_COOKIE['level'];

                if (!isset($data['appointments_id']) || !is_numeric($data['appointments_id'])) {
                    respond(false, "無效的預約 ID");
                }
                $appointments_id = $data['appointments_id'];

                $stmt = $conn->prepare("SELECT u_id, user_name, user_tel, car_model, service_type, appointment_date, car_status, estimated_price, actual_price FROM appointments WHERE appointments_id = ?");
                if (!$stmt) {
                    respond(false, "SQL 準備失敗: " . $conn->error);
                }
                $stmt->bind_param("i", $appointments_id);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result->num_rows == 0) {
                    respond(false, "預約 ID $appointments_id 不存在");
                }
                $appointment = $result->fetch_assoc();
                $stmt->close();

                if ($level == 2 && $appointment['u_id'] !== $u_id) {
                    respond(false, "您無權修改他人的預約");
                }
                if ($level == 2 && $appointment['car_status'] !== '待維修') {
                    respond(false, "僅能修改狀態為「待維修」的預約");
                }

                $user_name = isset($data['user_name']) ? trim($data['user_name']) : $appointment['user_name'];
                $user_tel = isset($data['user_tel']) ? trim($data['user_tel']) : $appointment['user_tel'];
                $car_model = isset($data['car_model']) ? trim($data['car_model']) : $appointment['car_model'];
                $service_type = isset($data['service_type']) ? trim($data['service_type']) : $appointment['service_type'];
                $appointment_date = isset($data['appointment_date']) ? trim($data['appointment_date']) : $appointment['appointment_date'];
                $car_status = isset($data['car_status']) ? trim($data['car_status']) : $appointment['car_status'];
                $estimated_price = isset($data['estimated_price']) && is_numeric($data['estimated_price']) ? floatval($data['estimated_price']) : $appointment['estimated_price'];
                $actual_price = isset($data['actual_price']) && is_numeric($data['actual_price']) ? floatval($data['actual_price']) : $appointment['actual_price'];

                if ($level == 2 && ($car_status !== '待維修' || isset($data['actual_price']))) {
                    respond(false, "一般會員無法更改預約狀態或實際價格");
                }

                if (strtotime($appointment_date) < time()) {
                    respond(false, "預約日期必須為未來時間");
                }

                $stmt = $conn->prepare("UPDATE appointments SET user_name = ?, user_tel = ?, car_model = ?, service_type = ?, appointment_date = ?, car_status = ?, estimated_price = ?, actual_price = ? WHERE appointments_id = ?");
                if (!$stmt) {
                    respond(false, "SQL 準備失敗: " . $conn->error);
                }
                $stmt->bind_param("sssssssdi", $user_name, $user_tel, $car_model, $service_type, $appointment_date, $car_status, $estimated_price, $actual_price, $appointments_id);
                if ($stmt->execute()) {
                    if ($stmt->affected_rows > 0) {
                        respond(true, "預約更新成功");
                    } else {
                        respond(false, "預約未變更");
                    }
                } else {
                    respond(false, "預約更新失敗: " . $stmt->error);
                }
            }
            break;

        case 'DELETE':
            if ($action === 'delete_reservation') {
                if (!isset($_COOKIE['u_id']) || !isset($_COOKIE['level'])) {
                    respond(false, "用戶未登入");
                }
                $u_id = $_COOKIE['u_id'];
                $suspension_check = check_suspension($conn, $u_id);
                if (!$suspension_check['state']) {
                    respond(false, $suspension_check['message']);
                }
                $level = $_COOKIE['level'];

                if (!isset($data['appointments_id']) || !is_numeric($data['appointments_id'])) {
                    respond(false, "無效的預約 ID");
                }
                $appointments_id = $data['appointments_id'];

                $stmt = $conn->prepare("SELECT u_id, car_status FROM appointments WHERE appointments_id = ?");
                if (!$stmt) {
                    respond(false, "SQL 準備失敗: " . $conn->error);
                }
                $stmt->bind_param("i", $appointments_id);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result->num_rows == 0) {
                    respond(false, "預約 ID $appointments_id 不存在");
                }
                $appointment = $result->fetch_assoc();
                $stmt->close();

                if ($level == 2) {
                    if ($appointment['u_id'] !== $u_id) {
                        respond(false, "您無權刪除他人的預約");
                    }
                    if ($appointment['car_status'] !== '待維修') {
                        respond(false, "僅能刪除狀態為「待維修」的預約");
                    }
                }

                $stmt = $conn->prepare("DELETE FROM appointments WHERE appointments_id = ?");
                if (!$stmt) {
                    respond(false, "SQL 準備失敗: " . $conn->error);
                }
                $stmt->bind_param("i", $appointments_id);
                if ($stmt->execute()) {
                    if ($stmt->affected_rows > 0) {
                        respond(true, "預約刪除成功");
                    } else {
                        respond(false, "刪除失敗，可能是資料庫錯誤");
                    }
                } else {
                    respond(false, "刪除失敗: " . $stmt->error);
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
    if (isset($stmt)) $stmt->close();
    if (isset($conn)) $conn->close();
}
