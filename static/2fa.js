document.addEventListener('DOMContentLoaded', () => {
  const codeInput = document.getElementById('code');
  const submitButton = document.querySelector('button[type="submit"]');

  // Disable the button by default on page load
  submitButton.disabled = true;

  // Function to check if code is exactly 6 digits
  function validateCode() {
    const code = codeInput.value;
    const isValid = /^\d{6}$/.test(code);  // regex means exactly 6 digits
    submitButton.disabled = !isValid;      // enable if valid, else disable
  }

  // Listen for user typing in the input box
  codeInput.addEventListener('input', (e) => {
    // Remove any non-digit characters
    e.target.value = e.target.value.replace(/\D/g, '');
    validateCode();
  });
});
