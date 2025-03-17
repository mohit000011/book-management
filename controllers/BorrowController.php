<?php
header("Content-Type: application/json");

require dirname(__DIR__) . '/includes/db.php';
require dirname(__DIR__) . '/middleware/auth.php';
require dirname(__DIR__) . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Dotenv\Dotenv;

// Load environment variables
$dotenv = Dotenv::createImmutable(__DIR__ . "/../");
$dotenv->load();

$key = $_ENV['JWT_SECRET']; // Load secret key from .env
$method = $_SERVER['REQUEST_METHOD']; // Get HTTP method

// Borrow a Book
if ($method == 'POST' && isset($_GET['action']) && $_GET['action'] == 'borrow') {
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

        $input = json_decode(file_get_contents("php://input"), true);
        if (empty($input['book_id'])) {
            http_response_code(400);
            echo json_encode(["error" => "Book ID is required"]);
            exit;
        }

        $book_id = $input['book_id'];

        // Check if book exists
        $stmt = $conn->prepare("SELECT id FROM books WHERE id = :book_id");
        $stmt->bindValue(":book_id", $book_id, PDO::PARAM_INT);
        $stmt->execute();
        if (!$stmt->fetch()) {
            http_response_code(404);
            echo json_encode(["error" => "Book not found"]);
            exit;
        }

        // Check if book is already borrowed by the user and not returned
        $stmt = $conn->prepare("SELECT id FROM borrowed_books WHERE user_id = :user_id AND book_id = :book_id AND returned_date IS NULL");
        $stmt->bindValue(":user_id", $user_id, PDO::PARAM_INT);
        $stmt->bindValue(":book_id", $book_id, PDO::PARAM_INT);
        $stmt->execute();
        if ($stmt->fetch()) {
            http_response_code(400);
            echo json_encode(["error" => "You already borrowed this book and haven't returned it yet"]);
            exit;
        }

        // Borrow book (insert record)
        $stmt = $conn->prepare("INSERT INTO borrowed_books (user_id, book_id) VALUES (:user_id, :book_id)");
        $stmt->bindValue(":user_id", $user_id, PDO::PARAM_INT);
        $stmt->bindValue(":book_id", $book_id, PDO::PARAM_INT);

        if ($stmt->execute()) {
            http_response_code(201);
            echo json_encode(["message" => "Book borrowed successfully"]);
        } else {
            http_response_code(500);
            echo json_encode(["error" => "Failed to borrow book"]);
        }

    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid token"]);
    }

    

    exit;
}

// Return a Book
if ($method == 'POST' && isset($_GET['action']) && $_GET['action'] == 'return') {
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

        $input = json_decode(file_get_contents("php://input"), true);
        if (empty($input['book_id'])) {
            http_response_code(400);
            echo json_encode(["error" => "Book ID is required"]);
            exit;
        }

        $book_id = $input['book_id'];

        // Check if book is borrowed by user
        $stmt = $conn->prepare("SELECT id FROM borrowed_books WHERE user_id = :user_id AND book_id = :book_id AND returned_date IS NULL");
        $stmt->bindValue(":user_id", $user_id, PDO::PARAM_INT);
        $stmt->bindValue(":book_id", $book_id, PDO::PARAM_INT);
        $stmt->execute();
        $borrowedBook = $stmt->fetch();

        if (!$borrowedBook) {
            http_response_code(400);
            echo json_encode(["error" => "You haven't borrowed this book or it is already returned"]);
            exit;
        }
         
        // Update return date
        $stmt = $conn->prepare("UPDATE borrowed_books SET returned_date = NOW() WHERE user_id = :user_id AND book_id = :book_id AND returned_date IS NULL");
        $stmt->bindValue(":user_id", $user_id, PDO::PARAM_INT);
        $stmt->bindValue(":book_id", $book_id, PDO::PARAM_INT);
        

        if ($stmt->execute()) {
            http_response_code(200);
            echo json_encode(["message" => "Book returned successfully"]);
        } else {
            http_response_code(500);
            echo json_encode(["error" => "Failed to return book"]);
        }

    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid token"]);
    }

    exit;
}

?>
