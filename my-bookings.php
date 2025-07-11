<?php
session_start();
require_once 'includes/config.php';
require_once 'includes/functions.php';

requireUserLogin();

$pageTitle = 'My Bookings';

// Get user's bookings
$db = getDB();
$stmt = $db->prepare("
    SELECT b.*, t.name as therapist_name 
    FROM bookings b 
    LEFT JOIN therapists t ON b.therapist_id = t.id 
    WHERE b.email = ? 
    ORDER BY b.created_at DESC
");
$stmt->execute([$_SESSION['user_email']]);
$bookings = $stmt->fetchAll();
?>

<?php include 'includes/header.php'; ?>

<section class="py-5">
    <div class="container">
        <div class="row">
            <div class="col-12">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2 class="fw-bold">My Bookings</h2>
                        <p class="text-muted mb-0">View and manage your spa appointments</p>
                    </div>
                    <a href="models.php" class="btn btn-primary">
                        <i class="bi bi-plus-lg me-2"></i>Book New Appointment
                    </a>
                </div>
                
                <?php if (empty($bookings)): ?>
                    <div class="text-center py-5">
                        <div class="auth-card">
                            <i class="bi bi-calendar-x display-4 text-muted mb-3"></i>
                            <h4 class="text-muted">No bookings found</h4>
                            <p class="text-muted mb-4">You haven't made any spa appointments yet.</p>
                            <a href="models.php" class="btn btn-primary">
                                <i class="bi bi-calendar-check me-2"></i>Book Your First Appointment
                            </a>
                        </div>
                    </div>
                <?php else: ?>
                    <div class="row g-4">
                        <?php foreach ($bookings as $booking): ?>
                            <div class="col-lg-6">
                                <div class="card h-100">
                                    <div class="card-header d-flex justify-content-between align-items-center">
                                        <h6 class="mb-0 fw-bold">Booking #<?php echo $booking['id']; ?></h6>
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
                                    </div>
                                    <div class="card-body">
                                        <div class="row g-3">
                                            <div class="col-12">
                                                <h5 class="text-primary"><?php echo htmlspecialchars($booking['therapist_name'] ?? 'N/A'); ?></h5>
                                            </div>
                                            
                                            <div class="col-md-6">
                                                <div class="d-flex align-items-center">
                                                    <i class="bi bi-calendar me-2 text-muted"></i>
                                                    <div>
                                                        <small class="text-muted">Date</small><br>
                                                        <strong><?php echo date('M j, Y', strtotime($booking['booking_date'])); ?></strong>
                                                    </div>
                                                </div>
                                            </div>
                                            
                                            <div class="col-md-6">
                                                <div class="d-flex align-items-center">
                                                    <i class="bi bi-clock me-2 text-muted"></i>
                                                    <div>
                                                        <small class="text-muted">Time</small><br>
                                                        <strong><?php echo date('g:i A', strtotime($booking['booking_time'])); ?></strong>
                                                    </div>
                                                </div>
                                            </div>
                                            
                                            <div class="col-md-6">
                                                <div class="d-flex align-items-center">
                                                    <i class="bi bi-currency-rupee me-2 text-muted"></i>
                                                    <div>
                                                        <small class="text-muted">Amount</small><br>
                                                        <strong class="text-success"><?php echo formatPrice($booking['total_amount']); ?></strong>
                                                    </div>
                                                </div>
                                            </div>
                                            
                                            <div class="col-md-6">
                                                <div class="d-flex align-items-center">
                                                    <i class="bi bi-credit-card me-2 text-muted"></i>
                                                    <div>
                                                        <small class="text-muted">Payment</small><br>
                                                        <strong><?php echo $booking['payment_id'] ? 'Paid Online' : 'Pay Later'; ?></strong>
                                                    </div>
                                                </div>
                                            </div>
                                            
                                            <?php if ($booking['message']): ?>
                                                <div class="col-12">
                                                    <div class="bg-light p-3 rounded">
                                                        <small class="text-muted">Special Requests:</small><br>
                                                        <?php echo htmlspecialchars($booking['message']); ?>
                                                    </div>
                                                </div>
                                            <?php endif; ?>
                                            
                                            <div class="col-12">
                                                <small class="text-muted">
                                                    <i class="bi bi-clock-history me-1"></i>
                                                    Booked <?php echo timeAgo($booking['created_at']); ?>
                                                </small>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="card-footer bg-transparent">
                                        <div class="d-flex gap-2">
                                            <?php if ($booking['status'] === 'pending'): ?>
                                                <button class="btn btn-outline-warning btn-sm" onclick="editBooking(<?php echo $booking['id']; ?>)">
                                                    <i class="bi bi-pencil me-1"></i>Edit
                                                </button>
                                                <button class="btn btn-outline-danger btn-sm" onclick="cancelBooking(<?php echo $booking['id']; ?>)">
                                                    <i class="bi bi-x-circle me-1"></i>Cancel
                                                </button>
                                            <?php endif; ?>
                                            
                                            <button class="btn btn-outline-primary btn-sm" onclick="contactSupport(<?php echo $booking['id']; ?>)">
                                                <i class="bi bi-headset me-1"></i>Contact Support
                                            </button>
                                            
                                            <?php if ($booking['status'] === 'completed'): ?>
                                                <button class="btn btn-outline-success btn-sm" onclick="rebookAppointment(<?php echo $booking['therapist_id']; ?>)">
                                                    <i class="bi bi-arrow-repeat me-1"></i>Book Again
                                                </button>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</section>

<!-- Edit Booking Modal -->
<div class="modal fade" id="editBookingModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header bg-gradient-primary text-white">
                <h5 class="modal-title">
                    <i class="bi bi-pencil me-2"></i>Edit Booking
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <form id="editBookingForm">
                <div class="modal-body">
                    <input type="hidden" id="editBookingId">
                    
                    <div class="mb-3">
                        <label class="form-label">New Date *</label>
                        <input type="date" class="form-control" id="editBookingDate" min="<?php echo date('Y-m-d'); ?>" required>
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label">New Time *</label>
                        <select class="form-control" id="editBookingTime" required>
                            <option value="">Select time</option>
                            <optgroup label="Regular Hours (8 AM - 8 PM)">
                                <option value="08:00">8:00 AM</option>
                                <option value="09:00">9:00 AM</option>
                                <option value="10:00">10:00 AM</option>
                                <option value="11:00">11:00 AM</option>
                                <option value="12:00">12:00 PM</option>
                                <option value="13:00">1:00 PM</option>
                                <option value="14:00">2:00 PM</option>
                                <option value="15:00">3:00 PM</option>
                                <option value="16:00">4:00 PM</option>
                                <option value="17:00">5:00 PM</option>
                                <option value="18:00">6:00 PM</option>
                                <option value="19:00">7:00 PM</option>
                                <option value="20:00">8:00 PM</option>
                            </optgroup>
                            <optgroup label="Night Hours (+₹1,500)">
                                <option value="21:00" data-night="true">9:00 PM (+₹1,500)</option>
                                <option value="22:00" data-night="true">10:00 PM (+₹1,500)</option>
                                <option value="23:00" data-night="true">11:00 PM (+₹1,500)</option>
                                <option value="00:00" data-night="true">12:00 AM (+₹1,500)</option>
                                <option value="01:00" data-night="true">1:00 AM (+₹1,500)</option>
                                <option value="02:00" data-night="true">2:00 AM (+₹1,500)</option>
                                <option value="03:00" data-night="true">3:00 AM (+₹1,500)</option>
                                <option value="04:00" data-night="true">4:00 AM (+₹1,500)</option>
                                <option value="05:00" data-night="true">5:00 AM (+₹1,500)</option>
                                <option value="06:00" data-night="true">6:00 AM (+₹1,500)</option>
                                <option value="07:00" data-night="true">7:00 AM (+₹1,500)</option>
                            </optgroup>
                        </select>
                        <small class="form-text text-muted">Night hours (8 PM - 8 AM) include additional ₹1,500 charge</small>
                    </div>
                    
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle me-2"></i>
                        <strong>Note:</strong> You can only edit bookings that are still pending confirmation.
                    </div>
                    
                    <!-- Price Update Display -->
                    <div id="priceUpdateSection" style="display: none;">
                        <div class="alert alert-warning">
                            <h6>Price Update:</h6>
                            <div id="priceComparison"></div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">
                        <i class="bi bi-check-lg me-2"></i>Update Booking
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<?php 
$extraScripts = '<script>
    let currentBookingData = {};
    
    function cancelBooking(bookingId) {
        if (confirm("Are you sure you want to cancel this booking? This action cannot be undone.")) {
            fetch("cancel_booking.php", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ booking_id: bookingId })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert("Booking cancelled successfully!");
                    location.reload();
                } else {
                    alert("Error: " + data.message);
                }
            })
            .catch(error => {
                console.error("Error:", error);
                alert("An error occurred while cancelling the booking.");
            });
        }
    }
    
    function editBooking(bookingId) {
        // Fetch booking details
        fetch("get_booking_for_edit.php?id=" + bookingId)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    currentBookingData = data.booking;
                    document.getElementById("editBookingId").value = bookingId;
                    document.getElementById("editBookingDate").value = data.booking.booking_date;
                    document.getElementById("editBookingTime").value = data.booking.booking_time;
                    
                    new bootstrap.Modal(document.getElementById("editBookingModal")).show();
                } else {
                    alert("Error loading booking details: " + data.message);
                }
            })
            .catch(error => {
                console.error("Error:", error);
                alert("Error loading booking details");
            });
    }
    
    // Handle time change to show price update
    document.getElementById("editBookingTime").addEventListener("change", function() {
        const selectedOption = this.options[this.selectedIndex];
        const isNight = selectedOption.dataset.night === "true";
        const currentIsNight = currentBookingData.is_night == 1;
        
        const priceUpdateSection = document.getElementById("priceUpdateSection");
        const priceComparison = document.getElementById("priceComparison");
        
        if (isNight !== currentIsNight) {
            const basePrice = parseFloat(currentBookingData.total_amount) - (currentIsNight ? 1500 : 0);
            const newTotal = basePrice + (isNight ? 1500 : 0);
            const currentTotal = parseFloat(currentBookingData.total_amount);
            
            priceComparison.innerHTML = `
                <div>Current Amount: ₹${currentTotal.toLocaleString("en-IN")}</div>
                <div>New Amount: ₹${newTotal.toLocaleString("en-IN")}</div>
                <div class="fw-bold ${newTotal > currentTotal ? "text-warning" : "text-success"}">
                    Difference: ${newTotal > currentTotal ? "+" : ""}₹${Math.abs(newTotal - currentTotal).toLocaleString("en-IN")}
                </div>
            `;
            priceUpdateSection.style.display = "block";
        } else {
            priceUpdateSection.style.display = "none";
        }
    });
    
    // Handle edit form submission
    document.getElementById("editBookingForm").addEventListener("submit", function(e) {
        e.preventDefault();
        
        const bookingId = document.getElementById("editBookingId").value;
        const newDate = document.getElementById("editBookingDate").value;
        const newTime = document.getElementById("editBookingTime").value;
        
        if (!newDate || !newTime) {
            alert("Please select both date and time.");
            return;
        }
        
        const selectedOption = document.getElementById("editBookingTime").options[document.getElementById("editBookingTime").selectedIndex];
        const isNight = selectedOption.dataset.night === "true";
        
        fetch("update_booking.php", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                booking_id: bookingId,
                booking_date: newDate,
                booking_time: newTime,
                is_night: isNight
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert("Booking updated successfully!");
                location.reload();
            } else {
                alert("Error: " + data.message);
            }
        })
        .catch(error => {
            console.error("Error:", error);
            alert("An error occurred while updating the booking.");
        });
    });
    
    // Reset modal when closed
    document.getElementById("editBookingModal").addEventListener("hidden.bs.modal", function() {
        document.getElementById("editBookingForm").reset();
        document.getElementById("priceUpdateSection").style.display = "none";
        currentBookingData = {};
    });
    
    function contactSupport(bookingId) {
        const message = `Hi, I need help with my booking #${bookingId}. Please assist me.`;
        const whatsappUrl = `https://wa.me/917005120041?text=${encodeURIComponent(message)}`;
        window.open(whatsappUrl, "_blank");
    }
    
    function rebookAppointment(therapistId) {
        window.location.href = `therapist-details.php?id=${therapistId}`;
    }
</script>';

include 'includes/footer.php'; 
?>