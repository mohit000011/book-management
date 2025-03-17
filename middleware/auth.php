<?php
require dirname(__DIR__) . '/vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__ . "/../");
$dotenv->load();
$key = $_ENV['JWT_SECRET'];

require dirname(__DIR__) . '/includes/db.php'; // Database connection

function authenticateUser() {
    global $key, $conn; // Include database connection

    $headers = getallheaders();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(["error" => "Authorization token required"]);
        exit;
    }

    $token = str_replace("Bearer ", "", $headers['Authorization']);

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));
        $user_id = $decoded->user_id;

        // Fetch user role from database
        $stmt = $conn->prepare("SELECT role FROM users WHERE id = :id");
        $stmt->bindParam(':id', $user_id, PDO::PARAM_INT);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            http_response_code(403);
            echo json_encode(["error" => "User not found"]);
            exit;
        }

        return [
            "user_id" => $user_id,
            "role" => $user['role']
        ];
    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid token"]);
        exit;
    }
}

function isAdmin() {
    $user = authenticateUser();
    if ($user['role'] !== 'admin') {
        http_response_code(403);
        echo json_encode(["error" => "Access denied. Admins only"]);
        exit;
    }
}
?>
