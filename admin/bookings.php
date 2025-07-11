<?php
session_start();
require_once '../includes/config.php';
require_once '../includes/functions.php';

requireAdminLogin();

$pageTitle = 'Manage Bookings';
$message = '';
$messageType = '';

// Handle status updates
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action = $_POST['action'];
    $bookingId = (int)$_POST['booking_id'];
    
    if ($action === 'update_status') {
        $status = $_POST['status'];
        $validStatuses = ['pending', 'confirmed', 'cancelled', 'completed'];
        
        if (in_array($status, $validStatuses)) {
            $db = getDB();
            $stmt = $db->prepare("UPDATE bookings SET status = ? WHERE id = ?");
            if ($stmt->execute([$status, $bookingId])) {
                $message = 'Booking status updated successfully!';
                $messageType = 'success';
            } else {
                $message = 'Failed to update booking status.';
                $messageType = 'danger';
            }
        }
    }
}

// Get all bookings
$bookings = getAllBookings();
?>

<?php include 'includes/admin_header.php'; ?>

<div class="admin-content">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h2 class="fw-bold">Manage Bookings</h2>
            <p class="text-muted mb-0">View and manage all customer bookings</p>
        </div>
        <div class="text-muted">
            <i class="bi bi-calendar3 me-1"></i>
            Total: <?php echo count($bookings); ?> bookings
        </div>
    </div>
    
    <?php if ($message): ?>
        <div class="alert alert-<?php echo $messageType; ?> alert-dismissible fade show">
            <i class="bi bi-<?php echo $messageType === 'success' ? 'check-circle' : 'exclamation-triangle'; ?> me-2"></i>
            <?php echo $message; ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>
    
    <div class="card">
        <div class="card-body">
            <?php if (empty($bookings)): ?>
                <div class="text-center py-5">
                    <i class="bi bi-calendar-x display-4 text-muted"></i>
                    <h5 class="text-muted mt-3">No bookings found</h5>
                    <p class="text-muted">Bookings will appear here once customers start making appointments.</p>
                </div>
            <?php else: ?>
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead class="table-light">
                            <tr>
                                <th>ID</th>
                                <th>Customer Details</th>
                                <th>Therapist</th>
                                <th>Appointment</th>
                                <th>Amount</th>
                                <th>Region</th>
                                <th>Payment Method</th>
                                <th>Payment Status</th>
                                <th>Status</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($bookings as $booking): 
                                // Determine payment method and status
                                    $paymentMethod = isset($booking['payment_id']) && $booking['payment_id'] ? 'Online' : 'Pay Later';
                                    $paymentStatus = isset($booking['payment_id']) && $booking['payment_id'] 
                                        ? ucfirst($booking['payment_status'] ?? 'completed') 
                                        : ($booking['status'] === 'completed' ? 'Paid' : 'Pending');
                                    $paymentBadgeClass = isset($booking['payment_id']) && $booking['payment_id'] 
                                        ? 'success' 
                                        : ($booking['status'] === 'completed' ? 'info' : 'warning');

                            ?>
                                <tr>
                                    <td>
                                        <span class="badge bg-light text-dark">#<?php echo $booking['id']; ?></span>
                                    </td>
                                    <td>
                                        <div>
                                            <strong><?php echo htmlspecialchars($booking['full_name']); ?></strong><br>
                                            <small class="text-muted">
                                                <i class="bi bi-envelope me-1"></i><?php echo htmlspecialchars($booking['email']); ?><br>
                                                <i class="bi bi-telephone me-1"></i><?php echo htmlspecialchars($booking['phone']); ?>
                                            </small>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="fw-medium"><?php echo htmlspecialchars($booking['therapist_name'] ?? 'N/A'); ?></span>
                                    </td>
                                    <td>
                                        <div>
                                            <i class="bi bi-calendar me-1"></i><?php echo date('M j, Y', strtotime($booking['booking_date'])); ?><br>
                                            <small class="text-muted">
                                                <i class="bi bi-clock me-1"></i><?php echo date('g:i A', strtotime($booking['booking_time'])); ?>
                                            </small>
                                        </div>
                                    </td>
                                    <td>
                                        <div>
                                            <span class="fw-bold text-success"><?php echo formatPrice($booking['total_amount']); ?></span>
                                            <?php if ($booking['is_night']): ?>
                                                <br><small class="text-warning">
                                                    <i class="bi bi-moon-stars me-1"></i>Night Service (+₹<?php echo number_format($booking['night_charge']); ?>)
                                                </small>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="badge bg-<?php echo $booking['region'] === 'ncr' ? 'primary' : 'info'; ?>">
                                            <?php echo $booking['region'] === 'ncr' ? 'Delhi-NCR' : 'Rest of India'; ?>
                                        </span>
                                    </td>
                                    <td>
                                        <span class="badge bg-<?php echo (isset($booking['payment_id']) && $booking['payment_id']) ? 'primary' : 'secondary'; ?>">
                                            <?php echo $paymentMethod; ?>
                                        </span>
                                        <?php if (isset($booking['payment_id']) && $booking['payment_id']): ?>
                                            <br><small class="text-muted">Razorpay</small>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <span class="badge bg-<?php echo $paymentBadgeClass; ?>">
                                            <?php echo $paymentStatus; ?>
                                        </span>
                                    </td>
                                    <td>
                                        <span class="badge bg-<?php 
                                            echo match($booking['status']) {
                                                'confirmed' => 'success',
                                                'pending' => 'warning',
                                                'cancelled' => 'danger',
                                                'completed' => 'info',
                                                default => 'secondary'
                                            };
                                        ?>">
                                            <?php echo ucfirst($booking['status']); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <small class="text-muted"><?php echo timeAgo($booking['created_at']); ?></small>
                                    </td>
                                    <td>
                                        <div class="btn-group btn-group-sm">
                                            <button class="btn btn-outline-info" onclick="viewBooking(<?php echo $booking['id']; ?>)" title="View Details">
                                                <i class="bi bi-eye"></i>
                                            </button>
                                            <div class="dropdown">
                                                <button class="btn btn-outline-primary dropdown-toggle" type="button" data-bs-toggle="dropdown" title="Update Status">
                                                    <i class="bi bi-gear"></i>
                                                </button>
                                                <ul class="dropdown-menu">
                                                    <li><h6 class="dropdown-header">Update Status</h6></li>
                                                    <li>
                                                        <form method="POST" style="display: inline;">
                                                            <input type="hidden" name="action" value="update_status">
                                                            <input type="hidden" name="booking_id" value="<?php echo $booking['id']; ?>">
                                                            <input type="hidden" name="status" value="confirmed">
                                                            <button type="submit" class="dropdown-item">
                                                                <i class="bi bi-check-circle text-success me-2"></i>Confirm
                                                            </button>
                                                        </form>
                                                    </li>
                                                    <li>
                                                        <form method="POST" style="display: inline;">
                                                            <input type="hidden" name="action" value="update_status">
                                                            <input type="hidden" name="booking_id" value="<?php echo $booking['id']; ?>">
                                                            <input type="hidden" name="status" value="completed">
                                                            <button type="submit" class="dropdown-item">
                                                                <i class="bi bi-check-all text-info me-2"></i>Complete
                                                            </button>
                                                        </form>
                                                    </li>
                                                    <li>
                                                        <form method="POST" style="display: inline;">
                                                            <input type="hidden" name="action" value="update_status">
                                                            <input type="hidden" name="booking_id" value="<?php echo $booking['id']; ?>">
                                                            <input type="hidden" name="status" value="cancelled">
                                                            <button type="submit" class="dropdown-item">
                                                                <i class="bi bi-x-circle text-danger me-2"></i>Cancel
                                                            </button>
                                                        </form>
                                                    </li>
                                                </ul>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Booking Details Modal -->
<div class="modal fade" id="bookingDetailsModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header bg-gradient-primary text-white">
                <h5 class="modal-title">
                    <i class="bi bi-calendar-check me-2"></i>Booking Details
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body" id="bookingDetailsModalBody">
                <!-- Content loaded via JavaScript -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<?php 
$extraScripts = '<script>
    function viewBooking(id) {
        // Show loading state
        document.getElementById("bookingDetailsModalBody").innerHTML = `
            <div class="text-center py-4">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="mt-2 text-muted">Loading booking details...</p>
            </div>
        `;
        
        // Show modal immediately with loading state
        new bootstrap.Modal(document.getElementById("bookingDetailsModal")).show();
        
        // Fetch booking details
        fetch("get_booking_details.php?id=" + id)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById("bookingDetailsModalBody").innerHTML = data.html;
                } else {
                    document.getElementById("bookingDetailsModalBody").innerHTML = `
                        <div class="alert alert-danger">
                            <i class="bi bi-exclamation-triangle me-2"></i>
                            Error loading booking details: ${data.message}
                        </div>
                    `;
                }
            })
            .catch(error => {
                console.error("Error:", error);
                document.getElementById("bookingDetailsModalBody").innerHTML = `
                    <div class="alert alert-danger">
                        <i class="bi bi-exclamation-triangle me-2"></i>
                        Error loading booking details. Please try again.
                    </div>
                `;
            });
    }
</script>';

include 'includes/admin_footer.php'; 
?>