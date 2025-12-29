/**
 * Dashboard JavaScript
 * Handles file upload and drag-and-drop functionality
 */

document.addEventListener('DOMContentLoaded', function() {
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    const uploadBtn = document.getElementById('uploadBtn');
    const uploadProgress = document.getElementById('uploadProgress');

    if (!uploadArea || !fileInput) return;

    // Click to upload
    uploadBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        fileInput.click();
    });

    uploadArea.addEventListener('click', function() {
        fileInput.click();
    });

    // File selection
    fileInput.addEventListener('change', function() {
        if (this.files.length > 0) {
            uploadFile(this.files[0]);
        }
    });

    // Drag and drop
    uploadArea.addEventListener('dragover', function(e) {
        e.preventDefault();
        e.stopPropagation();
        this.classList.add('drag-over');
    });

    uploadArea.addEventListener('dragleave', function(e) {
        e.preventDefault();
        e.stopPropagation();
        this.classList.remove('drag-over');
    });

    uploadArea.addEventListener('drop', function(e) {
        e.preventDefault();
        e.stopPropagation();
        this.classList.remove('drag-over');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            uploadFile(files[0]);
        }
    });

    // Upload file function
    function uploadFile(file) {
        // Validate file type
        const allowedExtensions = ['ipynb', 'txt', 'toml'];
        const extension = file.name.split('.').pop().toLowerCase();
        
        if (!allowedExtensions.includes(extension)) {
            showError('Please upload a .ipynb, requirements.txt, or pyproject.toml file');
            return;
        }

        // Show progress
        uploadArea.classList.add('hidden');
        uploadProgress.classList.remove('hidden');

        // Create form data
        const formData = new FormData();
        formData.append('file', file);

        // Upload
        fetch('/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.href = data.redirect;
            } else {
                showError(data.error || 'Upload failed');
                resetUpload();
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showError('Upload failed. Please try again.');
            resetUpload();
        });
    }

    function showError(message) {
        alert(message);
    }

    function resetUpload() {
        uploadArea.classList.remove('hidden');
        uploadProgress.classList.add('hidden');
        fileInput.value = '';
    }
});

// Collapsible vulnerability details
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('vuln-toggle')) {
        const details = e.target.closest('.vulnerability-item').querySelector('.vuln-details');
        if (details) {
            details.classList.toggle('expanded');
            e.target.textContent = details.classList.contains('expanded') ? 'Hide details' : 'Show details';
        }
    }
});

// Animate summary cards on load
document.addEventListener('DOMContentLoaded', function() {
    const cards = document.querySelectorAll('.summary-card');
    cards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, index * 100);
    });
});
