(() => {
  const input = document.getElementById('commandInput');
  const btn = document.getElementById('submitBtn');
  const result = document.getElementById('result');
  const form = document.getElementById('commandForm');

  function showResult(status, command, error) {
    result.className = `result ${status || ''}`;
    if (error) {
      result.innerHTML = `<div class="status">Error:</div><div>${error}</div>`;
      return;
    }
    const statusText = status === 'malicious' ? 'Malicious command' : 'Not malicious command';
    result.innerHTML = `<div class="status">${statusText}</div><div>${command}</div>`;
  }

  btn.addEventListener('click', async () => {
    const command = (input.value || '').trim();
    if (!command) {
      showResult('', '', 'Please enter a command.');
      return;
    }
    try {
      const res = await fetch('http://localhost:5000/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command })
      });
      if (!res.ok) throw new Error(`Server error: ${res.status}`);
      const data = await res.json();

      input.value = data.command || '';
      showResult(data.status, data.command);
    } catch (err) {
      showResult('', '', err.message || 'Request failed');
    }
  });

  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      btn.click();
    });
  }
})();
