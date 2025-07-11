// Region-based pricing system
class PricingManager {
    constructor() {
        this.currentRegion = this.getStoredRegion() || 'ncr'; // Default to NCR
        this.nightCharge = 1500;
        this.init();
    }
    
    init() {
        this.setupRegionModal();
        this.updateAllPrices();
        this.setupTimeSelection();
        this.updateRegionDisplay();
    }
    
    getStoredRegion() {
        return localStorage.getItem('selectedRegion') || 'ncr';
    }
    
    setRegion(region) {
        this.currentRegion = region;
        localStorage.setItem('selectedRegion', region);
        this.updateAllPrices();
        this.updateRegionDisplay();
        
        // Close modal if open
        const modal = bootstrap.Modal.getInstance(document.getElementById('regionModal'));
        if (modal) modal.hide();
    }
    
    setupRegionModal() {
        // Add event listeners
        document.addEventListener('click', (e) => {
            if (e.target.matches('.region-select-btn') || e.target.closest('.region-select-btn')) {
                const btn = e.target.matches('.region-select-btn') ? e.target : e.target.closest('.region-select-btn');
                const region = btn.dataset.region;
                this.setRegion(region);
            }
            
            // Legacy support for old region buttons
            if (e.target.matches('.region-btn')) {
                const region = e.target.dataset.region;
                this.setRegion(region);
            }
        });
    }
    
    updateRegionDisplay() {
        const buttons = document.querySelectorAll('.region-btn, .region-select-btn');
        buttons.forEach(btn => {
            btn.classList.toggle('active', btn.dataset.region === this.currentRegion);
        });
        
        // Update region text in navbar
        const regionText = document.getElementById('currentRegionText');
        if (regionText) {
            const regionName = this.currentRegion === 'ncr' ? 'Delhi-NCR' : 'Rest of India';
            regionText.textContent = regionName;
            
            // Update icon based on region
            const regionBtn = document.getElementById('regionPriceBtn');
            if (regionBtn) {
                const icon = regionBtn.querySelector('i');
                if (this.currentRegion === 'ncr') {
                    icon.className = 'bi bi-buildings me-1';
                } else {
                    icon.className = 'bi bi-geo-alt-fill me-1';
                }
            }
        }
    }
    
    updateAllPrices() {
        // Update therapist cards
        document.querySelectorAll('[data-therapist-id]').forEach(card => {
            this.updateTherapistPrice(card);
        });
        
        // Update booking modal if open
        this.updateBookingModalPrice();
    }
    
    updateTherapistPrice(card) {
        const therapistId = card.dataset.therapistId;
        const priceNcr = parseFloat(card.dataset.priceNcr || 0);
        const priceOther = parseFloat(card.dataset.priceOther || 0);
        
        const currentPrice = this.currentRegion === 'ncr' ? priceNcr : priceOther;
        
        // Update price display
        const priceElement = card.querySelector('.price-display');
        if (priceElement) {
            priceElement.innerHTML = `₹${currentPrice.toLocaleString('en-IN')}/session`;
        }
    }
    
    setupTimeSelection() {
        document.addEventListener('change', (e) => {
            if (e.target.matches('#bookingTimeSelect')) {
                this.updateBookingModalPrice();
            }
        });
    }
    
    updateBookingModalPrice() {
        const modal = document.getElementById('bookingModal');
        if (!modal || !modal.classList.contains('show')) return;
        
        // Get prices from modal data attributes (set when modal opens)
        const priceNcr = parseFloat(modal.dataset.therapistPriceNcr || 0);
        const priceOther = parseFloat(modal.dataset.therapistPriceOther || 0);
        
        if (priceNcr === 0 && priceOther === 0) return;
        
        const basePrice = this.currentRegion === 'ncr' ? priceNcr : priceOther;
        
        // Check if night time is selected from time dropdown
        const timeSelect = document.getElementById('bookingTimeSelect');
        const selectedOption = timeSelect?.options[timeSelect.selectedIndex];
        const isNight = selectedOption?.dataset.night === 'true' || false;
        const nightCharge = isNight ? this.nightCharge : 0;
        const totalPrice = basePrice + nightCharge;
        
        // Update price displays
        this.updatePriceBreakdown(basePrice, nightCharge, totalPrice);
        
        // Update hidden form fields
        const bookingAmount = document.getElementById('bookingAmount');
        if (bookingAmount) {
            bookingAmount.value = totalPrice;
        }
    }
    
    updatePriceBreakdown(basePrice, nightCharge, totalPrice) {
        const breakdownContainer = document.getElementById('priceBreakdown');
        if (!breakdownContainer) return;
        
        const regionName = this.currentRegion === 'ncr' ? 'Delhi-NCR' : 'Rest of India';
        
        let breakdownHTML = `
            <div class="price-breakdown">
                <div class="d-flex justify-content-between mb-2">
                    <span>Base Price (${regionName}):</span>
                    <span>₹${basePrice.toLocaleString('en-IN')}</span>
                </div>
        `;
        
        if (nightCharge > 0) {
            breakdownHTML += `
                <div class="d-flex justify-content-between text-warning mb-2">
                    <span>Night Time Charge:</span>
                    <span>₹${nightCharge.toLocaleString('en-IN')}</span>
                </div>
            `;
        }
        
        breakdownHTML += `
                <hr class="my-1">
                <div class="d-flex justify-content-between fw-bold text-success">
                    <span>Total Amount:</span>
                    <span>₹${totalPrice.toLocaleString('en-IN')}</span>
                </div>
            </div>
        `;
        
        breakdownContainer.innerHTML = breakdownHTML;
        
        // Update main display amount
        const displayAmount = document.getElementById('displayAmount');
        if (displayAmount) {
            displayAmount.textContent = `₹${totalPrice.toLocaleString('en-IN')}`;
        }
    }
    
    getBookingData() {
        return {
            region: this.currentRegion,
            isNight: this.isNightTimeSelected(),
            nightCharge: this.isNightTimeSelected() ? this.nightCharge : 0
        };
    }
    
    isNightTimeSelected() {
        const timeSelect = document.getElementById('bookingTimeSelect');
        const selectedOption = timeSelect?.options[timeSelect.selectedIndex];
        return selectedOption?.dataset.night === 'true' || false;
    }
}

// Global function for opening region modal
function openRegionModal() {
    const modal = new bootstrap.Modal(document.getElementById('regionModal'));
    modal.show();
}

// Initialize pricing manager when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.pricingManager = new PricingManager();
    
    // Update therapist detail page prices
    const priceAmount = document.querySelector('.price-amount');
    if (priceAmount) {
        const priceNcr = parseFloat(priceAmount.dataset.priceNcr || 0);
        const priceOther = parseFloat(priceAmount.dataset.priceOther || 0);
        const currentRegion = window.pricingManager.currentRegion;
        const currentPrice = currentRegion === 'ncr' ? priceNcr : priceOther;
        
        const priceValue = priceAmount.querySelector('.price-value');
        if (priceValue) {
            priceValue.textContent = currentPrice.toLocaleString('en-IN');
        }
    }
});

// Make functions globally available
window.openRegionModal = openRegionModal;
// Export for global access
window.PricingManager = PricingManager;