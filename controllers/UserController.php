<?php
header("Content-Type: application/json"); // Ensure JSON response

require dirname(__DIR__) . '/includes/db.php';
 // Database connection
require dirname(__DIR__) . '/middleware/auth.php'; // Token validation
require dirname(__DIR__) . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Dotenv\Dotenv;

// Load environment variables
$dotenv = Dotenv::createImmutable(__DIR__ . "/../");
$dotenv->load();

// Check if JWT_SECRET is properly loaded
if (!isset($_ENV['JWT_SECRET']) || empty($_ENV['JWT_SECRET'])) {
    http_response_code(500);
    echo json_encode(["error" => "Server configuration error: Missing JWT secret"]);
    exit;
}

$key = $_ENV['JWT_SECRET']; // Load secret key from .env

$method = $_SERVER['REQUEST_METHOD']; // Get HTTP method

// User Registration
if ($method == 'POST' && isset($_GET['action']) && $_GET['action'] == 'register') {
    $input = json_decode(file_get_contents("php://input"), true);

    if (empty($input['username']) || empty($input['email']) || empty($input['password'])) {
        http_response_code(400);
        echo json_encode(["error" => "All fields are required"]);
        exit;
    }
    // Check if email already exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = :email");
    $stmt->bindValue(":email", $input['email']);
    $stmt->execute();
    if ($stmt->fetch()) {
        http_response_code(400);
        echo json_encode(["error" => "Email already in use"]);
        exit;
    }

    // Hash password
    $hashedPassword = password_hash($input['password'], PASSWORD_BCRYPT);

    // Insert user into the database
    $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)");
    $stmt->bindValue(":username", $input['username']);
    $stmt->bindValue(":email", $input['email']);
    $stmt->bindValue(":password", $hashedPassword);

    if ($stmt->execute()) {
        http_response_code(201);
        echo json_encode(["message" => "User registered successfully"]);
    } else {
        http_response_code(500);
        echo json_encode(["error" => "Failed to register user"]);
    }
    exit;
}

// User Login
if ($method == 'POST' && isset($_GET['action']) && $_GET['action'] == 'login') {
    $input = json_decode(file_get_contents("php://input"), true);

    if (empty($input['email']) || empty($input['password'])) {
        http_response_code(400);
        echo json_encode(["error" => "Email and password are required"]);
        exit;
    }

    // Check if user exists
    $stmt = $conn->prepare("SELECT id, username, email, password FROM users WHERE email = :email");
    $stmt->bindValue(":email", $input['email']);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !password_verify($input['password'], $user['password'])) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid email or password"]);
        exit;
    }

    // Generate JWT token
    $payload = [
        "user_id" => $user['id'],
        "username" => $user['username'],
        "email" => $user['email'],
        "exp" => time() + 3600 // Token expires in 1 hour
    ];

    $token = JWT::encode($payload, $key, 'HS256');

    http_response_code(200);
    echo json_encode(["message" => "Login successful", "token" => $token]);
    exit;
}

// Get User Profile
if ($method == 'GET' && isset($_GET['action']) && $_GET['action'] == 'profile') {
    $decodedUser = authenticateUser(); // Validate token and get user data

    if (!$decodedUser || !isset($decodedUser->user_id)) {
        http_response_code(401);
        echo json_encode(["error" => "Unauthorized"]);
        exit;
    }

    // Fetch user details
    $stmt = $conn->prepare("SELECT id, username, email FROM users WHERE id = :id");
    $stmt->bindValue(":id", $decodedUser->user_id, PDO::PARAM_INT);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        http_response_code(200);
        echo json_encode($user);
    } else {
        http_response_code(404);
        echo json_encode(["error" => "User not found"]);
    }
    exit;
}

// Invalid request
http_response_code(400);
echo json_encode(["error" => "Invalid request"]);
exit;
