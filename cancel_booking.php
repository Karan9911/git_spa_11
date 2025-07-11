<?php
session_start();
require_once 'includes/config.php';
require_once 'includes/functions.php';

requireUserLogin();

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Invalid request method']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
$bookingId = (int)($input['booking_id'] ?? 0);

if ($bookingId <= 0) {
    echo json_encode(['success' => false, 'message' => 'Invalid booking ID']);
    exit;
}

try {
    $db = getDB();
    
    // Verify booking belongs to user and is cancellable
    $stmt = $db->prepare("
        SELECT id, status, booking_date, booking_time, email 
        FROM bookings 
        WHERE id = ? AND email = ?
    ");
    $stmt->execute([$bookingId, $_SESSION['user_email']]);
    $booking = $stmt->fetch();
    
    if (!$booking) {
        echo json_encode(['success' => false, 'message' => 'Booking not found or access denied']);
        exit;
    }
    
    if ($booking['status'] !== 'pending') {
        echo json_encode(['success' => false, 'message' => 'Only pending bookings can be cancelled']);
        exit;
    }
    
    // Check if booking is not in the past
    $bookingDateTime = $booking['booking_date'] . ' ' . $booking['booking_time'];
    if (strtotime($bookingDateTime) < time()) {
        echo json_encode(['success' => false, 'message' => 'Cannot cancel past bookings']);
        exit;
    }
    
    // Update booking status to cancelled
    $stmt = $db->prepare("UPDATE bookings SET status = 'cancelled' WHERE id = ?");
    $result = $stmt->execute([$bookingId]);
    
    if ($result) {
        echo json_encode([
            'success' => true, 
            'message' => 'Booking cancelled successfully'
        ]);
    } else {
        echo json_encode(['success' => false, 'message' => 'Failed to cancel booking']);
    }
    
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'An error occurred while cancelling the booking']);
}
?>