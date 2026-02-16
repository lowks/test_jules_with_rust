document.addEventListener('DOMContentLoaded', function() {
    const dateInput = document.getElementById('date');
    if (dateInput) {
        dateInput.addEventListener('keydown', function(event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                if (typeof this.form.requestSubmit === 'function') {
                    this.form.requestSubmit();
                } else {
                    this.form.submit();
                }
            }
        });
    }
});
