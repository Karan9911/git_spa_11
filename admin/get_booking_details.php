<?php
session_start();
require_once '../includes/config.php';
require_once '../includes/functions.php';

requireAdminLogin();

header('Content-Type: application/json');

if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    echo json_encode(['success' => false, 'message' => 'Invalid booking ID']);
    exit;
}

$bookingId = (int)$_GET['id'];

try {
    $db = getDB();
    $stmt = $db->prepare("
        SELECT b.*, t.name as therapist_name 
        FROM bookings b 
        LEFT JOIN therapists t ON b.therapist_id = t.id 
        WHERE b.id = ?
    ");
    $stmt->execute([$bookingId]);
    $booking = $stmt->fetch();

    if (!$booking) {
        echo json_encode(['success' => false, 'message' => 'Booking not found']);
        exit;
    }

    $hasPaymentId = isset($booking['payment_id']) && $booking['payment_id'];

    $paymentMethod = $hasPaymentId ? 'Online Payment (Razorpay)' : 'Pay Later';
    $paymentStatus = $hasPaymentId ? 
        ucfirst($booking['payment_status'] ?? 'completed') : 
        ($booking['status'] === 'completed' ? 'Paid at Spa' : 'Pending');

    // Generate HTML for modal
    $html = '
        <div class="row">
            <div class="col-md-6">
                <h6 class="fw-bold text-primary mb-3">Customer Information</h6>
                <div class="mb-2">
                    <strong>Name:</strong> ' . htmlspecialchars($booking['full_name']) . '
                </div>
                <div class="mb-2">
                    <strong>Email:</strong> ' . htmlspecialchars($booking['email']) . '
                </div>
                <div class="mb-2">
                    <strong>Phone:</strong> ' . htmlspecialchars($booking['phone']) . '
                </div>
            </div>
            <div class="col-md-6">
                <h6 class="fw-bold text-primary mb-3">Booking Details</h6>
                <div class="mb-2">
                    <strong>Therapist:</strong> ' . htmlspecialchars($booking['therapist_name'] ?? 'N/A') . '
                </div>
                <div class="mb-2">
                    <strong>Date:</strong> ' . date('M j, Y', strtotime($booking['booking_date'])) . '
                </div>
                <div class="mb-2">
                    <strong>Time:</strong> ' . date('g:i A', strtotime($booking['booking_time'])) . '
                </div>
                <div class="mb-2">
                    <strong>Status:</strong> <span class="badge bg-' . 
                        match($booking['status']) {
                            'confirmed' => 'success',
                            'pending' => 'warning',
                            'cancelled' => 'danger',
                            'completed' => 'info',
                            default => 'secondary'
                        } . '">' . ucfirst($booking['status']) . '</span>
                </div>
            </div>
            <div class="col-12 mt-3">
                <h6 class="fw-bold text-primary mb-3">Payment Information</h6>
                <div class="row">
                    <div class="col-md-4">
                        <div class="mb-2">
                            <strong>Amount:</strong> <span class="text-success fw-bold">' . formatPrice($booking['total_amount']) . '</span>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="mb-2">
                            <strong>Payment Method:</strong> ' . $paymentMethod . '
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="mb-2">
                            <strong>Payment Status:</strong> <span class="badge bg-' . 
                                ($hasPaymentId ? 'success' : 'warning') . '">' . $paymentStatus . '</span>
                        </div>
                    </div>
                </div>';

    if ($hasPaymentId) {
        $html .= '
                <div class="mt-2">
                    <small class="text-muted">
                        <strong>Payment ID:</strong> ' . htmlspecialchars($booking['payment_id']) . '
                    </small>
                </div>';
    }

    $html .= '
            </div>';

    if ($booking['message']) {
        $html .= '
            <div class="col-12 mt-3">
                <h6 class="fw-bold text-primary mb-3">Special Requests</h6>
                <div class="bg-light p-3 rounded">
                    ' . htmlspecialchars($booking['message']) . '
                </div>
            </div>';
    }

    $html .= '
            <div class="col-12 mt-3">
                <h6 class="fw-bold text-primary mb-3">Booking Timeline</h6>
                <div class="row">
                    <div class="col-md-6">
                        <small class="text-muted">
                            <strong>Booked on:</strong> ' . date('M j, Y g:i A', strtotime($booking['created_at'])) . '
                        </small>
                    </div>
                    <div class="col-md-6">
                        <small class="text-muted">
                            <strong>Booking ID:</strong> #' . $booking['id'] . '
                        </small>
                    </div>
                </div>
            </div>
        </div>';

    echo json_encode([
        'success' => true,
        'booking' => $booking,
        'html' => $html
    ]);

} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'Server error occurred']);
}
?>