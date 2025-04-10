<?php

use Ratchet\MessageComponentInterface;
use Ratchet\ConnectionInterface;
use Ratchet\Server\IoServer;
use Ratchet\Http\HttpServer;
use Ratchet\WebSocket\WsServer;

require dirname(__DIR__) . '/vendor/autoload.php';

class Chat implements MessageComponentInterface
{
    protected $clients;
    protected $userConnections;
    protected $adminConnections;
    protected $lastMessageTime; // 用於訊息限流

    public function __construct()
    {
        $this->clients = new \SplObjectStorage;
        $this->userConnections = [];
        $this->adminConnections = [];
        $this->lastMessageTime = [];
    }

    public function onOpen(ConnectionInterface $conn)
    {
        $this->clients->attach($conn);
        echo "新連線! ({$conn->resourceId})\n";
    }

    public function onMessage(ConnectionInterface $from, $msg)
    {
        $data = json_decode($msg, true);
        if (!isset($data['user_id']) || !isset($data['message']) || !isset($data['sender'])) {
            return;
        }

        $user_id = $data['user_id'];
        $sender = $data['sender'];
        $message = $data['message'];

        // 訊息限流：限制同一用戶每秒最多發送 5 條訊息
        $currentTime = microtime(true);
        if (isset($this->lastMessageTime[$user_id])) {
            $timeDiff = $currentTime - $this->lastMessageTime[$user_id];
            if ($timeDiff < 0.2) { // 每 0.2 秒最多 1 條訊息（即每秒 5 條）
                echo "訊息發送過快，user_id: $user_id\n";
                return;
            }
        }
        $this->lastMessageTime[$user_id] = $currentTime;

        // 將連線與用戶 ID 關聯
        if ($sender === "user") {
            if (!isset($this->userConnections[$user_id])) {
                $this->userConnections[$user_id] = [];
            }
            $this->userConnections[$user_id][] = $from;
        } elseif ($sender === "admin") {
            $this->adminConnections[] = $from;
        }

        // 儲存訊息到資料庫
        $created_at = date('Y-m-d H:i:s');
        $is_read = ($sender === 'admin') ? 1 : 0;

        $conn = mysqli_connect("localhost", "owner01", "123456", "Project");
        if (!$conn) {
            echo "資料庫連線失敗: " . mysqli_connect_error() . "\n";
            return;
        }
        mysqli_set_charset($conn, "utf8");

        // 插入訊息
        $stmt = $conn->prepare("INSERT INTO chat_messages (u_id, sender, message, created_at, is_read) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("ssssi", $user_id, $sender, $message, $created_at, $is_read);
        $stmt->execute();
        $stmt->close();

        // 如果是管理員發送訊息，將該用戶的所有訊息標記為已讀
        if ($sender === 'admin') {
            $update_stmt = $conn->prepare("UPDATE chat_messages SET is_read = 1 WHERE u_id = ? AND sender = 'user'");
            $update_stmt->bind_param("s", $user_id);
            $update_stmt->execute();
            $update_stmt->close();
        }
        $conn->close();

        // 準備推送的訊息資料
        $messageData = [
            'user_id' => $user_id,
            'sender' => $sender,
            'message' => $message,
            'created_at' => $created_at,
            'real_name' => $this->getRealName($user_id)
        ];

        // 推送給相關用戶
        if (isset($this->userConnections[$user_id])) {
            foreach ($this->userConnections[$user_id] as $client) {
                if ($client !== $from) {
                    $client->send(json_encode($messageData));
                }
            }
        }

        // 推送給所有管理員
        foreach ($this->adminConnections as $admin) {
            if ($admin !== $from) {
                $admin->send(json_encode($messageData));
            }
        }
    }

    private function getRealName($user_id)
    {
        $conn = mysqli_connect("localhost", "owner01", "123456", "Project");
        if (!$conn) {
            return "未知用戶";
        }
        mysqli_set_charset($conn, "utf8");
        $stmt = $conn->prepare("SELECT real_name FROM users WHERE user_id = ?");
        $stmt->bind_param("s", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();
        $conn->close();
        return $row['real_name'] ?? "未知用戶";
    }

    public function onClose(ConnectionInterface $conn)
    {
        $this->clients->detach($conn);
        foreach ($this->userConnections as $user_id => $connections) {
            $this->userConnections[$user_id] = array_filter($connections, function ($c) use ($conn) {
                return $c !== $conn;
            });
        }
        $this->adminConnections = array_filter($this->adminConnections, function ($c) use ($conn) {
            return $c !== $conn;
        });
        echo "連線關閉! ({$conn->resourceId})\n";
    }

    public function onError(ConnectionInterface $conn, \Exception $e)
    {
        echo "發生錯誤: {$e->getMessage()}\n";
        $conn->close();
    }
}

$server = IoServer::factory(
    new HttpServer(
        new WsServer(
            new Chat()
        )
    ),
    8080
);

$server->run();
